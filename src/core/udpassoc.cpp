#include "udpassoc.h"

#include "cidr.h"
#include "dnscache.h"
#include "logger.h"
#include "pipe.h"
#include "ruleengine.h"
#include "socksutil.h"

namespace qpr {

UdpAssoc::UdpAssoc(QUdpSocket *socket, Prepare prepare, bool remoteDns, Flow *flow, QObject *parent)
    : QObject(parent)
    , socket_(socket)
    , prepare_(std::move(prepare))
    , remoteDns_(remoteDns)
    , flow_(flow)
{
    socket_->setParent(this);
    connect(socket_, &QUdpSocket::readyRead, this, &UdpAssoc::onDatagram);
}

void UdpAssoc::onDatagram()
{
    while (socket_->hasPendingDatagrams()) {
        QByteArray packet;
        packet.resize(int(socket_->pendingDatagramSize()));
        QHostAddress sender;
        quint16 senderPort = 0;
        socket_->readDatagram(packet.data(), packet.size(), &sender, &senderPort);
        if (!haveClient_) {
            clientAddr_ = sender;
            clientPort_ = senderPort;
            haveClient_ = true;
        }
        const bool fromClient = sender == clientAddr_ && senderPort == clientPort_;
        if (fromClient) {
            if (flow_)
                flow_->addReceived(static_cast<quint64>(packet.size()));
            handleClientPacket(packet);
            continue;
        }
        if (relayReady_ && sender == relayAddr_ && senderPort == relayPort_) {
            socket_->writeDatagram(packet, clientAddr_, clientPort_);
            if (flow_)
                flow_->addSent(static_cast<quint64>(packet.size()));
            continue;
        }
        QString host = sender.toString();
        const QByteArray wrapped = socksUdpPacket(host, senderPort, packet);
        socket_->writeDatagram(wrapped, clientAddr_, clientPort_);
        if (flow_)
            flow_->addSent(static_cast<quint64>(wrapped.size()));
    }
}

void UdpAssoc::handleClientPacket(const QByteArray &packet)
{
    QString host;
    quint16 port = 0;
    QByteArray payload;
    QString error;
    const ParseStatus status = parseSocksUdpPacket(packet, &host, &port, &payload, &error);
    if (status != ParseStatus::Ok) {
        if (status == ParseStatus::Bad)
            Logger::instance()->warn(error);
        return;
    }
    Endpoint endpoint;
    if (flow_) {
        endpoint.process = flow_->snapshot().process;
        endpoint.pid = flow_->snapshot().pid;
    }
    endpoint.host = host;
    endpoint.port = port;
    endpoint.udp = true;
    if (isIpAddress(host))
        endpoint.ip = QHostAddress(host);
    auto go = [this, host, port, payload](Decision decision, Endpoint) {
        if (decision.needIp)
            decision.action = RuleAction::Direct;
        if (decision.action == RuleAction::Block) {
            Logger::instance()->info(QString::fromUtf8("UDP блок %1:%2").arg(host).arg(port));
            return;
        }
        const bool plainSocks = decision.hops.size() == 1
            && decision.hops.first().type == ProxyType::Socks5
            && !decision.hops.first().shield;
        if (decision.action == RuleAction::Direct || decision.hops.isEmpty()) {
            sendDirect(host, port, payload, decision);
            return;
        }
        if (plainSocks) {
            sendViaSocks(decision.hops.first(), host, port, payload);
            return;
        }
        if (!warned_) {
            warned_ = true;
            Logger::instance()->warn(QString::fromUtf8(
                "UDP через щит или цепочку пока не проксируется — пакет отброшен"));
        }
    };
    if (prepare_)
        prepare_(endpoint, go);
    else {
        Decision decision;
        decision.action = RuleAction::Direct;
        go(decision, endpoint);
    }
}

void UdpAssoc::sendDirect(const QString &host, quint16 port, const QByteArray &payload, const Decision &)
{
    auto send = [this, port, payload](const QHostAddress &address) {
        if (address.isNull())
            return;
        socket_->writeDatagram(payload, address, port);
    };
    if (isIpAddress(host)) {
        send(QHostAddress(host));
        return;
    }
    DnsCache::instance()->resolve(host, this, [send](QHostAddress address, QString) { send(address); });
}

void UdpAssoc::sendViaSocks(const Proxy &proxy, const QString &host, quint16 port, const QByteArray &payload)
{
    const QByteArray packet = socksUdpPacket(host, port, payload);
    if (!relayReady_) {
        relayQueue_.append(packet);
        ensureSocks(proxy);
        return;
    }
    socket_->writeDatagram(packet, relayAddr_, relayPort_);
}

void UdpAssoc::ensureSocks(const Proxy &proxy)
{
    if (relayPipe_ || relayFailed_)
        return;
    relayProxy_ = proxy;
    relayPipe_ = new SocketPipe(new QTcpSocket, this);
    connect(relayPipe_, &Pipe::ready, this, [this] {
        QByteArray hello;
        hello.append(char(0x05));
        hello.append(char(0x01));
        hello.append(char(relayProxy_.user.isEmpty() ? 0x00 : 0x02));
        relayPipe_->write(hello);
    });
    connect(relayPipe_, &Pipe::bytes, this, [this](const QByteArray &data) {
        relayBuf_.append(data);
        if (relayStage_ == 0) {
            if (relayBuf_.size() < 2)
                return;
            const quint8 method = quint8(relayBuf_.at(1));
            relayBuf_.remove(0, 2);
            if (method == 0x02) {
                QByteArray user = relayProxy_.user.toUtf8().left(255);
                QByteArray pass = relayProxy_.password.toUtf8().left(255);
                QByteArray auth;
                auth.append(char(1));
                auth.append(char(user.size()));
                auth.append(user);
                auth.append(char(pass.size()));
                auth.append(pass);
                relayPipe_->write(auth);
                relayStage_ = 1;
            } else if (method == 0x00) {
                relayPipe_->write(socks5UdpAssociateRequest());
                relayStage_ = 2;
            } else {
                relayFailed_ = true;
                return;
            }
        }
        if (relayStage_ == 1) {
            if (relayBuf_.size() < 2)
                return;
            if (quint8(relayBuf_.at(1)) != 0) {
                relayFailed_ = true;
                return;
            }
            relayBuf_.remove(0, 2);
            relayPipe_->write(socks5UdpAssociateRequest());
            relayStage_ = 2;
        }
        if (relayStage_ == 2) {
            int consumed = 0;
            Socks5Reply reply;
            QString error;
            const ParseStatus status = parseSocks5Reply(relayBuf_, &consumed, &reply, &error);
            if (status == ParseStatus::NeedMore)
                return;
            if (status != ParseStatus::Ok || reply.rep != 0) {
                relayFailed_ = true;
                Logger::instance()->error(QString::fromUtf8("UDP ASSOCIATE у прокси не удался"));
                return;
            }
            relayBuf_.remove(0, consumed);
            relayAddr_ = QHostAddress(reply.host);
            if (relayAddr_.isNull() || relayAddr_ == QHostAddress::Any || reply.host == QLatin1String("0.0.0.0"))
                relayAddr_ = relayPipe_->socket()->peerAddress();
            relayPort_ = reply.port;
            relayReady_ = true;
            for (const QByteArray &packet : relayQueue_)
                socket_->writeDatagram(packet, relayAddr_, relayPort_);
            relayQueue_.clear();
        }
    });
    connect(relayPipe_, &Pipe::finished, this, [this](const QString &) { relayFailed_ = true; });
    relayPipe_->connectTo(proxy.host, proxy.port, false, false);
}

} // namespace qpr
