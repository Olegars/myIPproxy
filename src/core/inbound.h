#pragma once

#include "flow.h"
#include "types.h"

#include <QHostAddress>
#include <QObject>
#include <functional>

class QTcpSocket;

class QTcpServer;

namespace qpr {

class InboundServer : public QObject {
    Q_OBJECT
public:
    struct Hooks {
        std::function<void(Endpoint endpoint, std::function<void(Decision, Endpoint)> done)> prepare;
        std::function<Flow *(FlowSnapshot snapshot)> makeFlow;
        std::function<bool()> remoteDns;
        std::function<bool()> rejectSelf;
        std::function<bool()> overloaded;
    };

    explicit InboundServer(QObject *parent = nullptr);
    void setHooks(Hooks hooks);
    bool listenSocks(const QHostAddress &address, quint16 port);
    bool listenHttp(const QHostAddress &address, quint16 port);
    void closeListeners();
    void handleRaw(QTcpSocket *socket, const QString &host, quint16 port, const QString &process, quint32 pid,
                   const QString &source);
    quint16 socksPort() const;
    quint16 httpPort() const;

private:
    void acceptSocks();
    void acceptHttp();

    Hooks hooks_;
    QTcpServer *socks_ = nullptr;
    QTcpServer *http_ = nullptr;
};

} // namespace qpr
