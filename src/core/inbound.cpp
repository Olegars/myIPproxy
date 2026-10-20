#include "inbound.h"

#include "dialer.h"
#include "logger.h"
#include "platform.h"
#include "ruleengine.h"
#include "socksutil.h"
#include "udpassoc.h"

#include <QCoreApplication>
#include <QDateTime>
#include <QHash>
#include <QNetworkProxy>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTimer>
#include <QUdpSocket>
#include <QUrl>

namespace qpr {
namespace {

FlowSnapshot baseSnap(const QString &process, quint32 pid, const QString &source, const QString &dest, bool udp)
{
    FlowSnapshot snap;
    snap.id = newId();
    snap.started = QDateTime::currentDateTime();
    snap.process = process.isEmpty() ? QString::fromUtf8("неизвестно") : process;
    snap.pid = pid;
    snap.source = source;
    snap.destination = dest;
    snap.status = QString::fromUtf8("Подключение");
    snap.udp = udp;
    return snap;
}

void warnSometimes(const QString &key, const QString &text)
{
    static QHash<QString, qint64> last;
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    if (now - last.value(key) < 5000)
        return;
    last.insert(key, now);
    Logger::instance()->warn(text);
}

bool tlsClientHelloReady(const QByteArray &data)
{
    if (data.isEmpty())
        return false;
    if (quint8(data.at(0)) != 0x16)
        return true;
    if (data.size() < 5)
        return false;
    const int recordLen = (quint8(data.at(3)) << 8) | quint8(data.at(4));
    if (recordLen <= 0 || recordLen > 20000)
        return true;
    return data.size() >= 5 + recordLen;
}

QString tlsServerName(const QByteArray &data)
{
    if (data.size() < 5 || quint8(data.at(0)) != 0x16)
        return {};
    const auto *p = reinterpret_cast<const unsigned char *>(data.constData());
    const int recordLen = (p[3] << 8) | p[4];
    if (recordLen <= 0 || data.size() < 5 + recordLen || p[5] != 0x01)
        return {};
    int i = 9;
    const int end = 5 + recordLen;
    if (i + 34 > end)
        return {};
    i += 34;
    if (i >= end)
        return {};
    const int sessionLen = p[i];
    i += 1 + sessionLen;
    if (i + 2 > end)
        return {};
    const int cipherLen = (p[i] << 8) | p[i + 1];
    i += 2 + cipherLen;
    if (i + 1 > end)
        return {};
    const int compLen = p[i];
    i += 1 + compLen;
    if (i + 2 > end)
        return {};
    const int extLen = (p[i] << 8) | p[i + 1];
    i += 2;
    const int extEnd = qMin(end, i + extLen);
    while (i + 4 <= extEnd) {
        const int type = (p[i] << 8) | p[i + 1];
        const int len = (p[i + 2] << 8) | p[i + 3];
        i += 4;
        if (i + len > extEnd)
            return {};
        if (type == 0 && len >= 5) {
            const int nameType = p[i + 2];
            const int nameLen = (p[i + 3] << 8) | p[i + 4];
            if (nameType == 0 && nameLen > 0 && i + 5 + nameLen <= extEnd)
                return QString::fromUtf8(reinterpret_cast<const char *>(p + i + 5), nameLen);
        }
        i += len;
    }
    return {};
}

class TcpSession : public QObject {
public:
    TcpSession(QTcpSocket *socket, InboundServer::Hooks hooks, bool http, QObject *parent)
        : QObject(parent)
        , hooks_(std::move(hooks))
        , http_(http)
    {
        pipe_ = new SocketPipe(socket, this);
        connect(pipe_, &Pipe::bytes, this, [this](const QByteArray &data) { onBytes(data); });
        connect(pipe_, &Pipe::finished, this, [this](const QString &) { deleteLater(); });
        pipe_->openExisting();
    }

    void startRaw(const QString &host, quint16 port, const QString &process, quint32 pid, const QString &sourceText)
    {
        raw_ = true;
        known_ = true;
        pid_ = pid;
        process_ = process;
        sourceOverride_ = sourceText;
        peekHost_ = host;
        peekPort_ = port;
        if (port == 443) {
            peek_ = true;
            peekTimer_ = new QTimer(this);
            peekTimer_->setSingleShot(true);
            connect(peekTimer_, &QTimer::timeout, this, [this] { finishPeek(); });
            peekTimer_->start(700);
            return;
        }
        begin(host, port, false);
    }

private:
    void onBytes(const QByteArray &data)
    {
        if (peek_) {
            buffer_ += data;
            if (tlsClientHelloReady(buffer_) || buffer_.size() > 16384)
                finishPeek();
            return;
        }
        if (phase_ == Phase::Dial)
            pending_ += data;
        else if (phase_ == Phase::Read)
            buffer_ += data;
        if (phase_ == Phase::Read)
            http_ ? pumpHttp() : pumpSocks();
    }

    void finishPeek()
    {
        if (!peek_)
            return;
        peek_ = false;
        if (peekTimer_)
            peekTimer_->stop();
        const QString name = tlsServerName(buffer_);
        pending_ += buffer_;
        buffer_.clear();
        begin(name.isEmpty() ? peekHost_ : name, peekPort_, false);
    }

    void pumpSocks()
    {
        if (buffer_.isEmpty())
            return;
        if (quint8(buffer_.at(0)) == 0x04) {
            pumpSocks4();
            return;
        }
        if (stage_ == 0) {
            if (buffer_.size() < 2)
                return;
            const int nmethods = quint8(buffer_.at(1));
            if (buffer_.size() < 2 + nmethods)
                return;
            buffer_.remove(0, 2 + nmethods);
            pipe_->write(socks5MethodReply(0x00));
            stage_ = 1;
            if (!buffer_.isEmpty())
                pumpSocks();
            return;
        }
        if (buffer_.size() < 4)
            return;
        QString error;
        Socks5Reply request;
        int consumed = 0;
        QByteArray fake = buffer_;
        fake[0] = 0x05;
        const ParseStatus status = parseSocks5Reply(fake, &consumed, &request, &error);
        if (status == ParseStatus::NeedMore)
            return;
        if (status == ParseStatus::Bad) {
            pipe_->write(socks5ServerReply(0x01, {}, 0));
            pipe_->abort();
            return;
        }
        buffer_.remove(0, consumed);
        const quint8 cmd = request.rep;
        if (cmd == 0x03) {
            beginUdp();
            return;
        }
        if (cmd != 0x01) {
            pipe_->write(socks5ServerReply(0x07, {}, 0));
            pipe_->abort();
            return;
        }
        begin(request.host, request.port, false);
    }

    void pumpSocks4()
    {
        const int zero = buffer_.indexOf('\0');
        if (zero < 0 || zero < 8)
            return;
        if (buffer_.size() < zero + 1)
            return;
        const quint16 port = (quint16(quint8(buffer_.at(2))) << 8) | quint8(buffer_.at(3));
        const quint32 ip = (quint32(quint8(buffer_.at(4))) << 24)
            | (quint32(quint8(buffer_.at(5))) << 16)
            | (quint32(quint8(buffer_.at(6))) << 8)
            | quint32(quint8(buffer_.at(7)));
        QString host = QHostAddress(ip).toString();
        int consumed = zero + 1;
        if (ip == 1) {
            const int end = buffer_.indexOf('\0', consumed);
            if (end < 0)
                return;
            host = QString::fromUtf8(buffer_.mid(consumed, end - consumed));
            consumed = end + 1;
        }
        buffer_.remove(0, consumed);
        socks4_ = true;
        begin(host, port, false);
    }

    void pumpHttp()
    {
        const int end = buffer_.indexOf(QByteArrayLiteral("\r\n\r\n"));
        if (end < 0) {
            if (buffer_.size() > 1024 * 1024)
                pipe_->abort();
            return;
        }
        const QByteArray head = buffer_.left(end);
        const QByteArray rest = buffer_.mid(end + 4);
        buffer_.clear();
        const int lineEnd = head.indexOf(QByteArrayLiteral("\r\n"));
        const QByteArray start = lineEnd >= 0 ? head.left(lineEnd) : head;
        const QList<QByteArray> parts = start.split(' ');
        if (parts.size() < 2) {
            pipe_->write(QByteArrayLiteral("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"));
            pipe_->abort();
            return;
        }
        const QByteArray method = parts.at(0).toUpper();
        const QByteArray target = parts.at(1);
        QString host;
        quint16 port = 80;
        if (method == QByteArrayLiteral("CONNECT")) {
            const QByteArray spec = target;
            if (spec.startsWith('[')) {
                const int rb = spec.indexOf(']');
                host = QString::fromUtf8(spec.mid(1, qMax(0, rb - 1)));
                port = rb > 0 ? spec.mid(rb + 2).toUShort() : 443;
            } else {
                const int colon = spec.lastIndexOf(':');
                host = QString::fromUtf8(colon > 0 ? spec.left(colon) : spec);
                port = colon > 0 ? spec.mid(colon + 1).toUShort() : 443;
            }
            httpConnect_ = true;
            pending_ += rest;
            begin(host, port, false);
            return;
        }
        QUrl url = QUrl::fromEncoded(target);
        if (url.scheme().isEmpty()) {
            const int hostPos = head.toLower().indexOf(QByteArrayLiteral("\r\nhost:"));
            if (hostPos >= 0) {
                const int value = head.indexOf(':', hostPos + 6);
                const int eol = head.indexOf(QByteArrayLiteral("\r\n"), value);
                const QByteArray hv = head.mid(value + 1, eol - value - 1).trimmed();
                const int colon = hv.lastIndexOf(':');
                host = QString::fromUtf8(colon > 0 ? hv.left(colon) : hv);
                port = colon > 0 ? hv.mid(colon + 1).toUShort() : 80;
            }
            url = QUrl();
            url.setPath(QString::fromUtf8(target.startsWith('/') ? target : QByteArrayLiteral("/") + target));
        } else {
            host = url.host();
            port = static_cast<quint16>(url.port(url.scheme() == QLatin1String("https") ? 443 : 80));
        }
        QByteArray path = url.path().toUtf8();
        if (path.isEmpty())
            path = QByteArrayLiteral("/");
        if (!url.query().isEmpty())
            path += QByteArrayLiteral("?") + url.query().toUtf8();
        const QByteArray tail = lineEnd >= 0 ? head.mid(lineEnd + 2) : QByteArray();
        earlyRequest_ = method + QByteArrayLiteral(" ") + path + QByteArrayLiteral(" HTTP/1.1\r\n") + tail
            + QByteArrayLiteral("\r\n\r\n") + rest;
        begin(host, port, false);
    }

    void beginUdp()
    {
        if (dropLoopOrFlood())
            return;
        ProcInfo proc = processForPeer(pipe_->socket()->peerAddress(), pipe_->socket()->peerPort(),
                                       pipe_->socket()->localPort());
        pid_ = proc.pid;
        process_ = proc.name;
        if (dropOwnProcess())
            return;
        auto *udp = new QUdpSocket(this);
        udp->setProxy(QNetworkProxy::NoProxy);
        if (!udp->bind(QHostAddress::LocalHost, 0, QUdpSocket::ShareAddress)) {
            pipe_->write(socks5ServerReply(0x01, {}, 0));
            pipe_->abort();
            delete udp;
            return;
        }
        const quint16 port = udp->localPort();
        pipe_->write(socks5ServerReply(0x00, QHostAddress(QStringLiteral("127.0.0.1")), port));
        auto *flow = makeFlow(baseSnap(processName(), pid_, source(), QString::fromUtf8("UDP"), true));
        if (!flow) {
            warnSometimes(QStringLiteral("cap"),
                          QString::fromUtf8("Слишком много соединений, новые пока отбрасываются."));
            pipe_->abort();
            delete udp;
            return;
        }
        flow->setStatus(QString::fromUtf8("Установлено"));
        udp->setParent(nullptr);
        new UdpAssoc(udp, hooks_.prepare, remoteDns(), flow, flow);
        connect(pipe_, &Pipe::finished, flow, [flow](const QString &) { flow->stop(); });
        phase_ = Phase::Dial;
        Logger::instance()->info(QString::fromUtf8("UDP ASSOCIATE от %1").arg(source()));
    }

    void begin(const QString &host, quint16 port, bool udp)
    {
        if (phase_ != Phase::Read)
            return;
        phase_ = Phase::Dial;
        pending_ += buffer_;
        buffer_.clear();
        if (dropLoopOrFlood())
            return;
        if (!known_) {
            ProcInfo proc = processForPeer(pipe_->socket()->peerAddress(), pipe_->socket()->peerPort(),
                                           pipe_->socket()->localPort());
            pid_ = proc.pid;
            process_ = proc.name;
            if (dropOwnProcess())
                return;
        }
        auto snap = baseSnap(processName(), pid_, source(),
                             QString::fromUtf8("%1:%2").arg(host).arg(port), udp);
        Endpoint endpoint;
        endpoint.process = snap.process;
        endpoint.pid = pid_;
        endpoint.host = host;
        endpoint.port = port;
        if (isIpLiteral(host))
            endpoint.ip = QHostAddress(host);
        Flow *flow = makeFlow(snap);
        if (!flow) {
            warnSometimes(QStringLiteral("cap"),
                          QString::fromUtf8("Слишком много соединений, новые пока отбрасываются."));
            reply(0x05, true);
            pipe_->abort();
            return;
        }
        connect(flow, &Flow::finished, this, [this] { pipe_->abort(); });
        auto prepared = [this, flow, host, port](Decision decision, Endpoint ep) {
            if (!flow)
                return;
            QString target = ep.host.isEmpty() ? host : ep.host;
            const QString via = describeVia(decision);
            const QString dest = QString::fromUtf8("%1:%2").arg(target).arg(port);
            flow->setRoute(via, decision.summary, dest);
            const QString process = flow->snapshot().process;
            if (decision.action == RuleAction::Block) {
                Logger::instance()->info(QString::fromUtf8("Блок %1 %2:%3 (%4)")
                                             .arg(process, target)
                                             .arg(port)
                                             .arg(decision.summary));
                reply(0x02, true);
                flow->setStatus(QString::fromUtf8("Заблокировано"));
                pipe_->abort();
                return;
            }
            if (decision.action != RuleAction::Direct) {
                Logger::instance()->info(QString::fromUtf8("%1 %2:%3 → %4")
                                             .arg(process, target)
                                             .arg(port)
                                             .arg(via));
            }
            auto *dialer = new Dialer(decision.hops, target, port, remoteDns(), this);
            connect(dialer, &Dialer::established, this, [this, dialer, flow](Pipe *upstream) {
                dialer->deleteLater();
                if (!upstream) {
                    reply(0x01, true);
                    flow->setStatus(QString::fromUtf8("Ошибка"), QString::fromUtf8("нет канала"));
                    pipe_->abort();
                    return;
                }
                reply(0x00, false);
                if (!earlyRequest_.isEmpty()) {
                    flow->addSent(static_cast<quint64>(earlyRequest_.size()));
                    upstream->write(earlyRequest_);
                    earlyRequest_.clear();
                }
                disconnect(pipe_, &Pipe::bytes, this, nullptr);
                pipe_->hold();
                if (!pending_.isEmpty())
                    pipe_->pushBack(pending_);
                pending_.clear();
                flow->attach(pipe_, upstream);
                setParent(flow);
            });
            connect(dialer, &Dialer::failed, this, [this, dialer, flow](const QString &error) {
                dialer->deleteLater();
                Logger::instance()->error(QString::fromUtf8("Не удалось открыть %1: %2")
                                              .arg(flow->snapshot().destination, error));
                reply(0x05, true);
                flow->setStatus(QString::fromUtf8("Ошибка"), error);
                pipe_->abort();
            });
            dialer->start();
        };
        if (hooks_.prepare)
            hooks_.prepare(endpoint, prepared);
        else {
            Decision decision;
            decision.action = RuleAction::Direct;
            decision.summary = QString::fromUtf8("напрямую");
            prepared(decision, endpoint);
        }
    }

    void reply(quint8 rep, bool failHttp)
    {
        if (raw_) {
            if (rep != 0)
                pipe_->abort();
            return;
        }
        if (http_) {
            if (httpConnect_) {
                pipe_->write(rep == 0
                                 ? QByteArrayLiteral("HTTP/1.1 200 Connection Established\r\n\r\n")
                                 : QByteArrayLiteral("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n"));
            } else if (failHttp || rep != 0) {
                pipe_->write(QByteArrayLiteral("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n"));
            }
            return;
        }
        if (socks4_) {
            QByteArray out;
            out.append(char(0));
            out.append(char(rep == 0 ? 0x5a : 0x5b));
            out.append(QByteArray(6, 0));
            pipe_->write(out);
            return;
        }
        pipe_->write(socks5ServerReply(rep, QHostAddress(QStringLiteral("0.0.0.0")), 0));
    }

    Flow *makeFlow(const FlowSnapshot &snapshot)
    {
        if (hooks_.makeFlow)
            return hooks_.makeFlow(snapshot);
        return new Flow(snapshot, this);
    }

    bool remoteDns() const
    {
        return hooks_.remoteDns ? hooks_.remoteDns() : true;
    }

    QString source() const
    {
        if (!sourceOverride_.isEmpty())
            return sourceOverride_;
        return QStringLiteral("%1:%2")
            .arg(pipe_->socket()->peerAddress().toString())
            .arg(pipe_->socket()->peerPort());
    }

    bool dropLoopOrFlood()
    {
        if (hooks_.overloaded && hooks_.overloaded()) {
            warnSometimes(QStringLiteral("cap"),
                          QString::fromUtf8("Слишком много соединений, новые пока отбрасываются."));
            pipe_->abort();
            return true;
        }
        return false;
    }

    bool dropOwnProcess()
    {
        if (!hooks_.rejectSelf || !hooks_.rejectSelf() || pid_ == 0)
            return false;
        if (pid_ != static_cast<quint32>(QCoreApplication::applicationPid()))
            return false;
        warnSometimes(QStringLiteral("self"),
                      QString::fromUtf8("Собственный трафик отброшен, чтобы не зациклиться через системный прокси."));
        pipe_->abort();
        return true;
    }

    QString processName() const
    {
        return process_.isEmpty() ? QString::fromUtf8("неизвестно") : process_;
    }

    static bool isIpLiteral(const QString &host)
    {
        QHostAddress addr;
        return addr.setAddress(host);
    }

    enum class Phase { Read, Dial };
    InboundServer::Hooks hooks_;
    SocketPipe *pipe_ = nullptr;
    bool http_ = false;
    bool raw_ = false;
    bool known_ = false;
    QString sourceOverride_;
    bool httpConnect_ = false;
    bool socks4_ = false;
    bool peek_ = false;
    QString peekHost_;
    quint16 peekPort_ = 0;
    QTimer *peekTimer_ = nullptr;
    Phase phase_ = Phase::Read;
    int stage_ = 0;
    QByteArray buffer_;
    QByteArray pending_;
    QByteArray earlyRequest_;
    quint32 pid_ = 0;
    QString process_;
};

} // namespace

InboundServer::InboundServer(QObject *parent)
    : QObject(parent)
{
}

void InboundServer::setHooks(Hooks hooks)
{
    hooks_ = std::move(hooks);
}

bool InboundServer::listenSocks(const QHostAddress &address, quint16 port)
{
    if (!socks_)
        socks_ = new QTcpServer(this);
    else
        socks_->close();
    connect(socks_, &QTcpServer::newConnection, this, &InboundServer::acceptSocks, Qt::UniqueConnection);
    if (!socks_->listen(address, port)) {
        Logger::instance()->error(QString::fromUtf8("SOCKS не слушает %1:%2 — %3")
                                     .arg(address.toString())
                                     .arg(port)
                                     .arg(socks_->errorString()));
        return false;
    }
    Logger::instance()->info(QString::fromUtf8("SOCKS5 слушает %1:%2")
                                 .arg(address.toString())
                                 .arg(socks_->serverPort()));
    return true;
}

bool InboundServer::listenHttp(const QHostAddress &address, quint16 port)
{
    if (!http_)
        http_ = new QTcpServer(this);
    else
        http_->close();
    connect(http_, &QTcpServer::newConnection, this, &InboundServer::acceptHttp, Qt::UniqueConnection);
    if (!http_->listen(address, port)) {
        Logger::instance()->error(QString::fromUtf8("HTTP-прокси не слушает %1:%2 — %3")
                                     .arg(address.toString())
                                     .arg(port)
                                     .arg(http_->errorString()));
        return false;
    }
    Logger::instance()->info(QString::fromUtf8("HTTP-прокси слушает %1:%2")
                                 .arg(address.toString())
                                 .arg(http_->serverPort()));
    return true;
}

void InboundServer::closeListeners()
{
    if (socks_)
        socks_->close();
    if (http_)
        http_->close();
}

quint16 InboundServer::socksPort() const
{
    return socks_ && socks_->isListening() ? socks_->serverPort() : 0;
}

quint16 InboundServer::httpPort() const
{
    return http_ && http_->isListening() ? http_->serverPort() : 0;
}

void InboundServer::handleRaw(QTcpSocket *socket, const QString &host, quint16 port, const QString &process,
                              quint32 pid, const QString &source)
{
    auto *session = new TcpSession(socket, hooks_, false, this);
    session->startRaw(host, port, process, pid, source);
}

void InboundServer::acceptSocks()
{
    while (socks_ && socks_->hasPendingConnections()) {
        QTcpSocket *socket = socks_->nextPendingConnection();
        if (hooks_.overloaded && hooks_.overloaded()) {
            warnSometimes(QStringLiteral("cap"),
                          QString::fromUtf8("Слишком много соединений, новые пока отбрасываются."));
            socket->abort();
            socket->deleteLater();
            continue;
        }
        new TcpSession(socket, hooks_, false, this);
    }
}

void InboundServer::acceptHttp()
{
    while (http_ && http_->hasPendingConnections()) {
        QTcpSocket *socket = http_->nextPendingConnection();
        if (hooks_.overloaded && hooks_.overloaded()) {
            warnSometimes(QStringLiteral("cap"),
                          QString::fromUtf8("Слишком много соединений, новые пока отбрасываются."));
            socket->abort();
            socket->deleteLater();
            continue;
        }
        new TcpSession(socket, hooks_, true, this);
    }
}

} // namespace qpr
