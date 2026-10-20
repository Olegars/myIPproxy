#include "hub.h"

#include "engine.h"
#include "logger.h"

#include <QDateTime>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTimer>
#include <QtEndian>

namespace qpr {
namespace {

QByteArray frame(const QJsonObject &message)
{
    const QByteArray body = QJsonDocument(message).toJson(QJsonDocument::Compact);
    QByteArray packet(4, 0);
    qToBigEndian(quint32(body.size()), packet.data());
    packet.append(body);
    return packet;
}

QJsonObject flowToJson(const FlowSnapshot &row)
{
    QJsonObject obj;
    obj.insert(QStringLiteral("id"), row.id);
    obj.insert(QStringLiteral("t"), row.started.toMSecsSinceEpoch());
    obj.insert(QStringLiteral("process"), row.process);
    obj.insert(QStringLiteral("pid"), int(row.pid));
    obj.insert(QStringLiteral("source"), row.source);
    obj.insert(QStringLiteral("destination"), row.destination);
    obj.insert(QStringLiteral("status"), row.status);
    obj.insert(QStringLiteral("via"), row.via);
    obj.insert(QStringLiteral("rule"), row.rule);
    obj.insert(QStringLiteral("sent"), QString::number(row.sent));
    obj.insert(QStringLiteral("received"), QString::number(row.received));
    obj.insert(QStringLiteral("error"), row.error);
    obj.insert(QStringLiteral("udp"), row.udp);
    return obj;
}

FlowSnapshot flowFromJson(const QJsonObject &obj)
{
    FlowSnapshot row;
    row.id = obj.value(QStringLiteral("id")).toString();
    row.started = QDateTime::fromMSecsSinceEpoch(obj.value(QStringLiteral("t")).toVariant().toLongLong());
    row.process = obj.value(QStringLiteral("process")).toString();
    row.pid = obj.value(QStringLiteral("pid")).toVariant().toUInt();
    row.source = obj.value(QStringLiteral("source")).toString();
    row.destination = obj.value(QStringLiteral("destination")).toString();
    row.status = obj.value(QStringLiteral("status")).toString();
    row.via = obj.value(QStringLiteral("via")).toString();
    row.rule = obj.value(QStringLiteral("rule")).toString();
    row.sent = obj.value(QStringLiteral("sent")).toString().toULongLong();
    row.received = obj.value(QStringLiteral("received")).toString().toULongLong();
    row.error = obj.value(QStringLiteral("error")).toString();
    row.udp = obj.value(QStringLiteral("udp")).toBool();
    return row;
}

bool takeMessage(QByteArray *buffer, QByteArray *body)
{
    if (buffer->size() < 4)
        return false;
    const quint32 size = qFromBigEndian<quint32>(buffer->constData());
    if (size > 8u * 1024u * 1024u) {
        buffer->clear();
        return false;
    }
    if (buffer->size() < int(4 + size))
        return false;
    *body = buffer->mid(4, int(size));
    buffer->remove(0, int(4 + size));
    return true;
}

} // namespace

HubServer::HubServer(Engine *engine, QObject *parent)
    : QObject(parent)
    , engine_(engine)
{
    connect(engine_, &Engine::listeningChanged, this, [this] { pushStatus(); });
    connect(engine_, &Engine::routingChanged, this, [this] { pushStatus(); });
    connect(Logger::instance(), &Logger::logged, this, [this](LogLevel level, const QDateTime &time, const QString &text) {
        QJsonObject message;
        message.insert(QStringLiteral("op"), QStringLiteral("log"));
        message.insert(QStringLiteral("level"), int(level));
        message.insert(QStringLiteral("ms"), time.toMSecsSinceEpoch());
        message.insert(QStringLiteral("text"), text);
        broadcast(message);
    });
    auto *timer = new QTimer(this);
    timer->setInterval(500);
    connect(timer, &QTimer::timeout, this, [this] { pushFlows(); });
    timer->start();
}

bool HubServer::start()
{
    server_ = new QTcpServer(this);
    if (!server_->listen(QHostAddress::LocalHost, kHubPort)) {
        Logger::instance()->error(QString::fromUtf8("Канал службы не открылся: %1").arg(server_->errorString()));
        return false;
    }
    connect(server_, &QTcpServer::newConnection, this, [this] { accept(); });
    Logger::instance()->info(QString::fromUtf8("Служба stopRKN слушает команды на 127.0.0.1:%1").arg(kHubPort));
    return true;
}

void HubServer::accept()
{
    while (server_->hasPendingConnections()) {
        QTcpSocket *socket = server_->nextPendingConnection();
        clients_.append(socket);
        connect(socket, &QTcpSocket::readyRead, this, [this, socket] { readSocket(socket); });
        connect(socket, &QTcpSocket::disconnected, this, [this, socket] {
            clients_.removeAll(socket);
            buffers_.remove(socket);
            socket->deleteLater();
        });
        pushStatus();
        pushFlows();
    }
}

void HubServer::readSocket(QTcpSocket *socket)
{
    buffers_[socket].append(socket->readAll());
    QByteArray body;
    while (takeMessage(&buffers_[socket], &body))
        handle(socket, body);
}

void HubServer::handle(QTcpSocket *socket, const QByteArray &body)
{
    const QJsonObject message = QJsonDocument::fromJson(body).object();
    const QString op = message.value(QStringLiteral("op")).toString();
    if (op == QLatin1String("hello")) {
        pushStatus();
        pushFlows();
        return;
    }
    if (op == QLatin1String("reload")) {
        engine_->reload();
        pushStatus();
        pushFlows();
        return;
    }
    if (op == QLatin1String("closeFlow")) {
        engine_->closeFlow(message.value(QStringLiteral("id")).toString());
        return;
    }
    if (op == QLatin1String("closePid")) {
        engine_->closePid(message.value(QStringLiteral("pid")).toVariant().toUInt());
        return;
    }
    if (op == QLatin1String("clearClosed"))
        engine_->clearClosed();
    Q_UNUSED(socket);
}

void HubServer::send(QTcpSocket *socket, const QJsonObject &message)
{
    if (socket && socket->state() == QAbstractSocket::ConnectedState)
        socket->write(frame(message));
}

void HubServer::broadcast(const QJsonObject &message)
{
    const QByteArray packet = frame(message);
    for (QTcpSocket *socket : clients_) {
        if (socket->state() == QAbstractSocket::ConnectedState)
            socket->write(packet);
    }
}

void HubServer::pushStatus()
{
    QJsonObject message;
    message.insert(QStringLiteral("op"), QStringLiteral("status"));
    message.insert(QStringLiteral("listening"), engine_->listening());
    message.insert(QStringLiteral("socks"), engine_->socksPort());
    message.insert(QStringLiteral("http"), engine_->httpPort());
    message.insert(QStringLiteral("shield"), engine_->shieldPort());
    message.insert(QStringLiteral("divert"), engine_->divertActive());
    message.insert(QStringLiteral("divertPort"), engine_->divertPort());
    broadcast(message);
}

void HubServer::pushFlows()
{
    QJsonArray rows;
    const QList<FlowSnapshot> snaps = engine_->snapshots();
    for (const FlowSnapshot &row : snaps)
        rows.append(flowToJson(row));
    QJsonObject message;
    message.insert(QStringLiteral("op"), QStringLiteral("flows"));
    message.insert(QStringLiteral("rows"), rows);
    broadcast(message);
}

HubClient::HubClient(QObject *parent)
    : QObject(parent)
    , socket_(new QTcpSocket(this))
{
    connect(socket_, &QTcpSocket::readyRead, this, [this] { readSocket(); });
    connect(socket_, &QTcpSocket::disconnected, this, [this] {
        ready_ = false;
        emit disconnected();
    });
}

bool HubClient::waitForService(int timeoutMs)
{
    socket_->connectToHost(QHostAddress::LocalHost, kHubPort);
    if (!socket_->waitForConnected(timeoutMs))
        return false;
    QJsonObject hello;
    hello.insert(QStringLiteral("op"), QStringLiteral("hello"));
    send(hello);
    if (socket_->bytesAvailable())
        readSocket();
    int left = timeoutMs;
    while (!ready_ && left > 0) {
        if (socket_->waitForReadyRead(50))
            readSocket();
        left -= 50;
    }
    return ready_;
}

void HubClient::reload()
{
    QJsonObject message;
    message.insert(QStringLiteral("op"), QStringLiteral("reload"));
    send(message);
}

void HubClient::closeFlow(const QString &id)
{
    QJsonObject message;
    message.insert(QStringLiteral("op"), QStringLiteral("closeFlow"));
    message.insert(QStringLiteral("id"), id);
    send(message);
}

void HubClient::closePid(quint32 pid)
{
    QJsonObject message;
    message.insert(QStringLiteral("op"), QStringLiteral("closePid"));
    message.insert(QStringLiteral("pid"), int(pid));
    send(message);
}

void HubClient::clearClosed()
{
    QJsonObject message;
    message.insert(QStringLiteral("op"), QStringLiteral("clearClosed"));
    send(message);
}

void HubClient::send(const QJsonObject &message)
{
    if (socket_->state() == QAbstractSocket::ConnectedState)
        socket_->write(frame(message));
}

void HubClient::readSocket()
{
    buffer_.append(socket_->readAll());
    QByteArray body;
    while (takeMessage(&buffer_, &body))
        handle(body);
}

void HubClient::handle(const QByteArray &body)
{
    const QJsonObject message = QJsonDocument::fromJson(body).object();
    const QString op = message.value(QStringLiteral("op")).toString();
    if (op == QLatin1String("status")) {
        ready_ = true;
        emit statusReceived(message.value(QStringLiteral("listening")).toBool(),
                            quint16(message.value(QStringLiteral("socks")).toInt()),
                            quint16(message.value(QStringLiteral("http")).toInt()),
                            quint16(message.value(QStringLiteral("shield")).toInt()),
                            message.value(QStringLiteral("divert")).toBool(),
                            quint16(message.value(QStringLiteral("divertPort")).toInt()));
        return;
    }
    if (op == QLatin1String("flows")) {
        QList<FlowSnapshot> rows;
        for (const QJsonValue &value : message.value(QStringLiteral("rows")).toArray())
            rows.append(flowFromJson(value.toObject()));
        emit flowsReceived(rows);
        return;
    }
    if (op == QLatin1String("log")) {
        emit logReceived(LogLevel(message.value(QStringLiteral("level")).toInt()),
                         QDateTime::fromMSecsSinceEpoch(message.value(QStringLiteral("ms")).toVariant().toLongLong()),
                         message.value(QStringLiteral("text")).toString());
    }
}

} // namespace qpr
