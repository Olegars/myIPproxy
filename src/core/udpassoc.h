#pragma once

#include "flow.h"
#include "types.h"

#include <QObject>
#include <QUdpSocket>
#include <functional>

namespace qpr {

class UdpAssoc : public QObject {
    Q_OBJECT
public:
    using Prepare = std::function<void(Endpoint, std::function<void(Decision, Endpoint)>)>;

    UdpAssoc(QUdpSocket *socket, Prepare prepare, bool remoteDns, Flow *flow, QObject *parent = nullptr);

private:
    void onDatagram();
    void handleClientPacket(const QByteArray &packet);
    void sendDirect(const QString &host, quint16 port, const QByteArray &payload, const Decision &decision);
    void sendViaSocks(const Proxy &proxy, const QString &host, quint16 port, const QByteArray &payload);
    void ensureSocks(const Proxy &proxy);

    QUdpSocket *socket_ = nullptr;
    Prepare prepare_;
    bool remoteDns_ = true;
    Flow *flow_ = nullptr;
    QHostAddress clientAddr_;
    quint16 clientPort_ = 0;
    bool haveClient_ = false;
    QHostAddress relayAddr_;
    quint16 relayPort_ = 0;
    bool relayReady_ = false;
    bool relayFailed_ = false;
    class SocketPipe *relayPipe_ = nullptr;
    QByteArray relayBuf_;
    int relayStage_ = 0;
    Proxy relayProxy_;
    QList<QByteArray> relayQueue_;
    bool warned_ = false;
};

} // namespace qpr
