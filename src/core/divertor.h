#pragma once

#include "types.h"

#include <QObject>

class QTcpServer;

namespace qpr {

class InboundServer;

class PacketDivert : public QObject {
    Q_OBJECT
public:
    explicit PacketDivert(InboundServer *inbound, QObject *parent = nullptr);
    ~PacketDivert() override;

    void setConfig(const AppConfig &config);
    bool start();
    void stop();
    bool active() const { return active_; }
    quint16 port() const { return port_; }

private:
    void loop();
    void socketLoop();
    bool onPacket(unsigned char *buffer, unsigned length, void *meta);
    void accept(QTcpServer *server, int family);

    InboundServer *inbound_ = nullptr;
    void *library_ = nullptr;
    void *handle_ = nullptr;
    void *socketHandle_ = nullptr;
    bool active_ = false;
    bool running_ = false;
    bool ipv6_ = false;
    quint16 port_ = 10802;
    class Private;
    Private *d_ = nullptr;
};

} // namespace qpr
