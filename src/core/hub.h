#pragma once

#include "types.h"

#include <QHash>
#include <QJsonObject>
#include <QList>
#include <QObject>

class QTcpServer;
class QTcpSocket;

namespace qpr {

class Engine;

constexpr quint16 kHubPort = 10803;

class HubServer : public QObject {
    Q_OBJECT
public:
    explicit HubServer(Engine *engine, QObject *parent = nullptr);
    bool start();

private:
    void accept();
    void readSocket(QTcpSocket *socket);
    void handle(QTcpSocket *socket, const QByteArray &body);
    void send(QTcpSocket *socket, const QJsonObject &message);
    void broadcast(const QJsonObject &message);
    void pushStatus();
    void pushFlows();

    Engine *engine_ = nullptr;
    QTcpServer *server_ = nullptr;
    QList<QTcpSocket *> clients_;
    QHash<QTcpSocket *, QByteArray> buffers_;
};

class HubClient : public QObject {
    Q_OBJECT
public:
    explicit HubClient(QObject *parent = nullptr);
    bool waitForService(int timeoutMs);
    bool active() const { return ready_; }
    void reload();
    void closeFlow(const QString &id);
    void closePid(quint32 pid);
    void clearClosed();

signals:
    void statusReceived(bool listening, quint16 socks, quint16 http, quint16 shield, bool divert, quint16 divertPort);
    void flowsReceived(const QList<qpr::FlowSnapshot> &rows);
    void logReceived(qpr::LogLevel level, const QDateTime &time, const QString &text);
    void disconnected();

private:
    void send(const QJsonObject &message);
    void readSocket();
    void handle(const QByteArray &body);

    QTcpSocket *socket_ = nullptr;
    QByteArray buffer_;
    bool ready_ = false;
};

} // namespace qpr
