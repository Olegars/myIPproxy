#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef _WIN32_WINNT
#    define _WIN32_WINNT 0x0601
#  endif
#  include <winsock2.h>
#  include <windows.h>
#endif

#include "divertor.h"

#include "divert_win.h"
#include "inbound.h"
#include "logger.h"
#include "platform.h"
#include "ruleengine.h"

#include <QCoreApplication>
#include <QDateTime>
#include <QHash>
#include <QHostAddress>
#include <QMutex>
#include <QMutexLocker>
#include <QTcpServer>
#include <QTcpSocket>

#include <atomic>
#include <cstring>
#include <thread>

namespace qpr {
namespace {

constexpr quint16 kPort = 10802;

quint16 readPort(const unsigned char *tcp, int offset)
{
    quint16 value = 0;
    std::memcpy(&value, tcp + offset, 2);
    return ntohs(value);
}

void writePort(unsigned char *tcp, int offset, quint16 port)
{
    const quint16 value = htons(port);
    std::memcpy(tcp + offset, &value, 2);
}

void writeBytes(unsigned char *dest, const unsigned char *src, int size)
{
    std::memcpy(dest, src, size_t(size));
}

QString formatAddress(int family, const unsigned char *bytes)
{
    if (family == 4) {
        quint32 net = 0;
        std::memcpy(&net, bytes, 4);
        return QHostAddress(ntohl(net)).toString();
    }
    Q_IPV6ADDR addr{};
    std::memcpy(&addr, bytes, 16);
    return QHostAddress(addr).toString();
}

QString divertFailure(unsigned code)
{
    if (code == ERROR_ACCESS_DENIED)
        return QString::fromUtf8("нужны права администратора");
    if (code == ERROR_FILE_NOT_FOUND || code == ERROR_MOD_NOT_FOUND || code == ERROR_PATH_NOT_FOUND)
        return QString::fromUtf8("рядом с программой нет WinDivert.dll и WinDivert64.sys");
    if (code == ERROR_INVALID_PARAMETER)
        return QString::fromUtf8("фильтр отклонён");
    if (code == 577)
        return QString::fromUtf8("драйвер WinDivert заблокирован защитой Windows");
    return QString::fromUtf8("код %1").arg(code);
}

bool browserNeedsSiteName(const QString &process, quint16 port)
{
    if (port != 443)
        return false;
    const QString name = process.toLower();
    return name == QLatin1String("browser.exe") || name == QLatin1String("chrome.exe")
        || name == QLatin1String("msedge.exe") || name == QLatin1String("opera.exe")
        || name == QLatin1String("brave.exe") || name == QLatin1String("vivaldi.exe");
}

struct Nat {
    int family = 4;
    unsigned char src[16]{};
    unsigned char dst[16]{};
    quint16 dstPort = 0;
    unsigned ifIdx = 0;
    unsigned subIfIdx = 0;
    RuleAction action = RuleAction::Direct;
    QString process;
    quint32 pid = 0;
    qint64 seen = 0;
};

struct SocketNote {
    quint32 pid = 0;
    quint16 remotePort = 0;
    QString process;
    qint64 seen = 0;
};

quint32 natKey(int family, quint16 port)
{
    return (quint32(family) << 16) | port;
}

} // namespace

class PacketDivert::Private {
public:
    QMutex mutex;
    AppConfig config;
    QHash<quint32, Nat> flows;
    QHash<quint32, SocketNote> sockets;
    std::atomic<bool> run{false};
    std::thread thread;
    std::thread socketsThread;
    quint32 self = 0;
};

PacketDivert::PacketDivert(InboundServer *inbound, QObject *parent)
    : QObject(parent)
    , inbound_(inbound)
    , d_(new Private)
{
    d_->self = GetCurrentProcessId();
}

PacketDivert::~PacketDivert()
{
    stop();
    delete d_;
}

void PacketDivert::setConfig(const AppConfig &config)
{
    QMutexLocker lock(&d_->mutex);
    d_->config = config;
}

bool PacketDivert::start()
{
    if (active_)
        return true;
    auto *v4 = new QTcpServer(this);
    if (!v4->listen(QHostAddress::LocalHost, kPort)) {
        Logger::instance()->error(QString::fromUtf8("Прозрачный порт %1 занят: %2")
                                     .arg(kPort)
                                     .arg(v4->errorString()));
        delete v4;
        return false;
    }
    port_ = v4->serverPort();
    connect(v4, &QTcpServer::newConnection, this, [this, v4] { accept(v4, 4); });

    auto *v6 = new QTcpServer(this);
    ipv6_ = v6->listen(QHostAddress::LocalHostIPv6, port_);
    if (ipv6_)
        connect(v6, &QTcpServer::newConnection, this, [this, v6] { accept(v6, 6); });
    else {
        delete v6;
        v6 = nullptr;
        Logger::instance()->warn(QString::fromUtf8("Прозрачный IPv6-порт не открылся, IPv6-соединения пойдут мимо прокси."));
    }

    const QString dll = QCoreApplication::applicationDirPath() + QStringLiteral("/WinDivert.dll");
    library_ = divert_load(reinterpret_cast<const wchar_t *>(dll.utf16()));
    if (!library_) {
        Logger::instance()->error(QString::fromUtf8(
            "WinDivert не загрузился: положите WinDivert.dll и WinDivert64.sys рядом с stopRKN.exe. "
            "Защитник Windows часто удаляет этот драйвер, его нужно разрешить."));
        v4->close();
        delete v4;
        if (v6) {
            v6->close();
            delete v6;
        }
        ipv6_ = false;
        return false;
    }
    unsigned error = 0;
    d_->run = true;
    socketHandle_ = divert_open(library_, "(tcp or udp) and (event == CONNECT or event == CLOSE)", DIVERT_LAYER_SOCKET,
                                DIVERT_FLAG_SNIFF | DIVERT_FLAG_RECV_ONLY, &error);
    if (socketHandle_)
        d_->socketsThread = std::thread([this] { socketLoop(); });
    else
        Logger::instance()->warn(QString::fromUtf8("Слой сокетов WinDivert не открылся (%1), процесс берётся из таблицы TCP.")
                                     .arg(divertFailure(error)));
    const QByteArray networkFilter = QStringLiteral(
                                         "(tcp and not impostor and ((outbound and !loopback) or (loopback and tcp.SrcPort == %1)))"
                                         " or (udp and not impostor and outbound and !loopback and udp.DstPort == 443)")
                                         .arg(port_)
                                         .toLatin1();
    handle_ = divert_open(library_, networkFilter.constData(), DIVERT_LAYER_NETWORK, 0, &error);
    if (!handle_) {
        Logger::instance()->error(QString::fromUtf8("WinDivert не запустился: %1. Пока работает только SOCKS/HTTP.")
                                     .arg(divertFailure(error)));
        d_->run = false;
        if (socketHandle_)
            divert_shutdown(library_, socketHandle_);
        if (d_->socketsThread.joinable())
            d_->socketsThread.join();
        if (socketHandle_) {
            divert_close(library_, socketHandle_);
            socketHandle_ = nullptr;
        }
        divert_unload(library_);
        library_ = nullptr;
        v4->close();
        delete v4;
        if (v6) {
            v6->close();
            delete v6;
        }
        ipv6_ = false;
        return false;
    }
    d_->thread = std::thread([this] { loop(); });
    active_ = true;
    Logger::instance()->info(QString::fromUtf8(
        "Перехват TCP через WinDivert, порт %1. Через прокси идут только программы из правил, остальной TCP не трогается.")
                                 .arg(port_));
    return true;
}

void PacketDivert::stop()
{
    d_->run = false;
    if (handle_)
        divert_shutdown(library_, handle_);
    if (socketHandle_)
        divert_shutdown(library_, socketHandle_);
    if (d_->thread.joinable())
        d_->thread.join();
    if (d_->socketsThread.joinable())
        d_->socketsThread.join();
    if (handle_) {
        divert_close(library_, handle_);
        handle_ = nullptr;
    }
    if (socketHandle_) {
        divert_close(library_, socketHandle_);
        socketHandle_ = nullptr;
    }
    if (library_) {
        divert_unload(library_);
        library_ = nullptr;
    }
    const auto servers = findChildren<QTcpServer *>();
    for (QTcpServer *server : servers) {
        server->close();
        delete server;
    }
    QMutexLocker lock(&d_->mutex);
    d_->flows.clear();
    d_->sockets.clear();
    active_ = false;
    ipv6_ = false;
}

void PacketDivert::socketLoop()
{
    unsigned char buffer[256];
    while (d_->run) {
        DivertMeta meta;
        unsigned length = 0;
        if (!divert_recv(library_, socketHandle_, buffer, sizeof(buffer), &length, &meta)) {
            const DWORD err = GetLastError();
            if (!d_->run || err == ERROR_NO_DATA || err == ERROR_INVALID_HANDLE)
                break;
            Sleep(5);
            continue;
        }
        unsigned event = 0;
        unsigned pid = 0;
        unsigned localPort = 0;
        unsigned remotePort = 0;
        unsigned protocol = 0;
        if (!divert_read_socket(&meta, &event, &pid, &localPort, &remotePort, &protocol) || localPort == 0
            || localPort > 65535)
            continue;
        const quint32 key = (protocol << 16) | localPort;
        if (event == 7) {
            QMutexLocker lock(&d_->mutex);
            d_->sockets.remove(key);
            continue;
        }
        if (event != 4 || pid == 0)
            continue;
        SocketNote note;
        note.pid = pid;
        note.remotePort = static_cast<quint16>(remotePort);
        note.process = processNameForPid(pid);
        note.seen = QDateTime::currentMSecsSinceEpoch();
        QMutexLocker lock(&d_->mutex);
        if (d_->sockets.size() > 4000) {
            const auto keys = d_->sockets.keys();
            for (quint32 old : keys) {
                if (note.seen - d_->sockets.value(old).seen > 60000)
                    d_->sockets.remove(old);
            }
        }
        d_->sockets.insert(key, note);
    }
}

void PacketDivert::loop()
{
    unsigned char buffer[65536];
    while (d_->run) {
        DivertMeta meta;
        unsigned length = 0;
        if (!divert_recv(library_, handle_, buffer, sizeof(buffer), &length, &meta)) {
            const DWORD err = GetLastError();
            if (!d_->run || err == ERROR_NO_DATA || err == ERROR_INVALID_HANDLE)
                break;
            Sleep(5);
            continue;
        }
        if (!onPacket(buffer, length, &meta))
            divert_send(library_, handle_, buffer, length, &meta, 0);
    }
}

bool PacketDivert::onPacket(unsigned char *buffer, unsigned length, void *metaPtr)
{
    auto *meta = static_cast<DivertMeta *>(metaPtr);
    unsigned char *ip4 = nullptr;
    unsigned char *ip6 = nullptr;
    unsigned char *tcp = nullptr;
    unsigned char *udp = nullptr;
    if (!divert_parse(library_, buffer, length, &ip4, &ip6, &tcp, &udp) || (!ip4 && !ip6) || (!tcp && !udp))
        return false;
    const int family = ip4 ? 4 : 6;
    const auto socketProc = [this](unsigned protocol, quint16 localPort, quint16 remotePort) {
        ProcInfo info;
        QMutexLocker lock(&d_->mutex);
        const auto it = d_->sockets.constFind((quint32(protocol) << 16) | localPort);
        if (it == d_->sockets.cend())
            return info;
        if (remotePort != 0 && it->remotePort != 0 && it->remotePort != remotePort)
            return info;
        info.pid = it->pid;
        info.name = it->process;
        return info;
    };
    if (!tcp) {
        if (static_cast<unsigned>(udp - buffer) + 8 > length || meta->loopback)
            return false;
        const quint16 udpSrc = readPort(udp, 0);
        const quint16 udpDst = readPort(udp, 2);
        if (udpDst != 443)
            return false;
        ProcInfo proc = socketProc(17, udpSrc, udpDst);
        if (proc.pid == 0)
            proc = processForUdp(udpSrc, family == 6, true);
        if (proc.pid == 0 || proc.pid == d_->self)
            return false;
        Endpoint endpoint;
        endpoint.process = proc.name;
        endpoint.pid = proc.pid;
        endpoint.port = udpDst;
        AppConfig config;
        {
            QMutexLocker lock(&d_->mutex);
            config = d_->config;
        }
        const Decision decision = matchRules(config, endpoint);
        if (decision.action != RuleAction::Proxy && decision.action != RuleAction::Chain
            && decision.action != RuleAction::Block && !browserNeedsSiteName(proc.name, udpDst))
            return false;
        static qint64 lastQuic = 0;
        const qint64 now = QDateTime::currentMSecsSinceEpoch();
        if (now - lastQuic > 5000) {
            lastQuic = now;
            Logger::instance()->warn(QString::fromUtf8(
                "UDP 443 у %1 отброшен: прокси умеет только TCP, программа должна перейти на TCP.")
                                         .arg(proc.name));
        }
        return true;
    }
    if (family == 6 && !ipv6_)
        return false;
    if (static_cast<unsigned>(tcp - buffer) + 20 > length)
        return false;
    if (family == 4 && static_cast<unsigned>(ip4 - buffer) + 20 > length)
        return false;
    if (family == 6 && static_cast<unsigned>(ip6 - buffer) + 40 > length)
        return false;
    const int addrBytes = family == 4 ? 4 : 16;
    unsigned char *src = family == 4 ? ip4 + 12 : ip6 + 8;
    unsigned char *dst = family == 4 ? ip4 + 16 : ip6 + 24;
    if (family == 4 && dst[0] >= 224)
        return false;
    const quint16 srcPort = readPort(tcp, 0);
    const quint16 dstPort = readPort(tcp, 2);
    const quint8 flags = tcp[13];
    const bool syn = (flags & 0x02) != 0;
    const bool ack = (flags & 0x10) != 0;
    const bool rst = (flags & 0x04) != 0;
    const qint64 now = QDateTime::currentMSecsSinceEpoch();

    if (meta->loopback && srcPort == port_) {
        Nat nat;
        bool found = false;
        {
            QMutexLocker lock(&d_->mutex);
            const auto it = d_->flows.constFind(natKey(family, dstPort));
            if (it != d_->flows.cend() && it->action == RuleAction::Proxy) {
                nat = it.value();
                d_->flows[natKey(family, dstPort)].seen = now;
                found = true;
            }
        }
        if (!found)
            return false;
        writeBytes(src, nat.dst, addrBytes);
        writeBytes(dst, nat.src, addrBytes);
        writePort(tcp, 0, nat.dstPort);
        if (ip4)
            std::memset(ip4 + 10, 0, 2);
        std::memset(tcp + 16, 0, 2);
        meta->outbound = 0;
        meta->loopback = 0;
        meta->ipv6 = family == 6;
        meta->ifIdx = nat.ifIdx;
        meta->subIfIdx = nat.subIfIdx;
        if (!divert_send(library_, handle_, buffer, length, meta, 1)) {
            static qint64 lastBack = 0;
            if (now - lastBack > 5000) {
                lastBack = now;
                Logger::instance()->error(QString::fromUtf8("Не удалось вернуть ответ программе, код %1")
                                              .arg(GetLastError()));
            }
        }
        if (rst) {
            QMutexLocker lock(&d_->mutex);
            d_->flows.remove(natKey(family, dstPort));
        }
        return true;
    }

    if (meta->loopback)
        return false;

    const quint32 key = natKey(family, srcPort);
    Nat nat;
    bool have = false;
    {
        QMutexLocker lock(&d_->mutex);
        const auto it = d_->flows.constFind(key);
        if (it != d_->flows.cend()) {
            nat = it.value();
            have = true;
        }
    }
    const bool handshake = syn && !ack;
    if (handshake || !have) {
        QHostAddress srcAddr;
        QHostAddress dstAddr;
        if (family == 4) {
            quint32 srcNet = 0;
            quint32 dstNet = 0;
            std::memcpy(&srcNet, src, 4);
            std::memcpy(&dstNet, dst, 4);
            srcAddr = QHostAddress(ntohl(srcNet));
            dstAddr = QHostAddress(ntohl(dstNet));
        } else {
            Q_IPV6ADDR srcIp{};
            Q_IPV6ADDR dstIp{};
            std::memcpy(&srcIp, src, 16);
            std::memcpy(&dstIp, dst, 16);
            srcAddr = QHostAddress(srcIp);
            dstAddr = QHostAddress(dstIp);
        }
        ProcInfo proc;
        if (handshake) {
            proc = socketProc(6, srcPort, dstPort);
            if (proc.pid == 0)
                proc = processForPeer(srcAddr, srcPort, dstPort, true);
            if (proc.pid == 0) {
                Sleep(20);
                proc = socketProc(6, srcPort, dstPort);
                if (proc.pid == 0)
                    proc = processForPeer(srcAddr, srcPort, dstPort, true);
            }
        }
        Nat fresh;
        fresh.family = family;
        writeBytes(fresh.src, src, addrBytes);
        writeBytes(fresh.dst, dst, addrBytes);
        fresh.dstPort = dstPort;
        fresh.ifIdx = meta->ifIdx;
        fresh.subIfIdx = meta->subIfIdx;
        fresh.process = proc.name.isEmpty() ? QString::fromUtf8("неизвестно") : proc.name;
        fresh.pid = proc.pid;
        fresh.seen = now;
        fresh.action = RuleAction::Direct;
        if (!handshake || (proc.pid != 0 && proc.pid == d_->self))
            fresh.action = RuleAction::Direct;
        else {
            Endpoint endpoint;
            endpoint.process = fresh.process;
            endpoint.pid = proc.pid;
            endpoint.host = dstAddr.toString();
            endpoint.ip = dstAddr;
            endpoint.port = dstPort;
            AppConfig config;
            {
                QMutexLocker lock(&d_->mutex);
                config = d_->config;
            }
            const Decision decision = matchRules(config, endpoint);
            if (decision.action == RuleAction::Proxy || decision.action == RuleAction::Chain)
                fresh.action = decision.hops.isEmpty() ? RuleAction::Block : RuleAction::Proxy;
            else
                fresh.action = decision.action;
            const bool peekName = fresh.action == RuleAction::Direct
                && browserNeedsSiteName(fresh.process, dstPort);
            if (peekName)
                fresh.action = RuleAction::Proxy;
            if (!peekName && fresh.action == RuleAction::Proxy && (!have || nat.action != RuleAction::Proxy))
                Logger::instance()->info(QString::fromUtf8("Перехват %1 → %2:%3")
                                             .arg(fresh.process, endpoint.host)
                                             .arg(dstPort));
        }
        {
            QMutexLocker lock(&d_->mutex);
            if (d_->flows.size() > 8000) {
                const auto keys = d_->flows.keys();
                for (quint32 old : keys) {
                    if (now - d_->flows.value(old).seen > 120000)
                        d_->flows.remove(old);
                }
            }
            d_->flows.insert(key, fresh);
        }
        nat = fresh;
    } else {
        QMutexLocker lock(&d_->mutex);
        d_->flows[key].seen = now;
    }

    if (rst) {
        QMutexLocker lock(&d_->mutex);
        d_->flows.remove(key);
    }
    if (nat.action == RuleAction::Block)
        return true;
    if (nat.action != RuleAction::Proxy)
        return false;

    const unsigned char v4Loop[4] = {127, 0, 0, 1};
    unsigned char v6Loop[16] = {};
    v6Loop[15] = 1;
    writeBytes(src, family == 4 ? v4Loop : v6Loop, addrBytes);
    writeBytes(dst, family == 4 ? v4Loop : v6Loop, addrBytes);
    writePort(tcp, 2, port_);
    if (ip4)
        std::memset(ip4 + 10, 0, 2);
    std::memset(tcp + 16, 0, 2);
    // Пакет на локальный порт можно вставить только как исходящий loopback.
    // Входящий loopback WinDivert не доставляет до слушающего сокета.
    meta->outbound = 1;
    meta->loopback = 1;
    meta->ipv6 = family == 6;
    if (!divert_send(library_, handle_, buffer, length, meta, 1)) {
        static qint64 lastSend = 0;
        if (now - lastSend > 5000) {
            lastSend = now;
            Logger::instance()->error(QString::fromUtf8("Не удалось отдать пакет локальному порту, код %1")
                                          .arg(GetLastError()));
        }
    }
    return true;
}

void PacketDivert::accept(QTcpServer *server, int family)
{
    while (server->hasPendingConnections()) {
        QTcpSocket *socket = server->nextPendingConnection();
        Nat nat;
        bool found = false;
        {
            QMutexLocker lock(&d_->mutex);
            const auto it = d_->flows.constFind(natKey(family, socket->peerPort()));
            if (it != d_->flows.cend()) {
                nat = it.value();
                found = true;
            }
        }
        if (!found || nat.action != RuleAction::Proxy) {
            socket->abort();
            socket->deleteLater();
            continue;
        }
        const QString host = formatAddress(nat.family, nat.dst);
        const QString source = formatAddress(nat.family, nat.src) + QLatin1Char(':') + QString::number(socket->peerPort());
        inbound_->handleRaw(socket, host, nat.dstPort, nat.process, nat.pid, source);
    }
}

} // namespace qpr
