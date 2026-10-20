#include "flow.h"

#include <QAbstractSocket>

namespace qpr {
namespace {
const qint64 kHigh = 1024 * 1024;
const qint64 kLow = 256 * 1024;
}

Flow::Flow(FlowSnapshot snapshot, QObject *parent)
    : QObject(parent)
    , snap_(std::move(snapshot))
{
    if (snap_.id.isEmpty())
        snap_.id = newId();
    if (!snap_.started.isValid())
        snap_.started = QDateTime::currentDateTime();
}

void Flow::setStatus(const QString &status, const QString &error)
{
    snap_.status = status;
    if (!error.isEmpty())
        snap_.error = error;
    emit changed();
}

void Flow::setRoute(const QString &via, const QString &rule, const QString &destination)
{
    snap_.via = via;
    snap_.rule = rule;
    if (!destination.isEmpty())
        snap_.destination = destination;
    emit changed();
}

void Flow::addSent(quint64 bytes)
{
    snap_.sent += bytes;
}

void Flow::addReceived(quint64 bytes)
{
    snap_.received += bytes;
}

void Flow::attach(Pipe *client, Pipe *upstream)
{
    client_ = client;
    upstream_ = upstream;
    if (client_)
        client_->setParent(this);
    if (upstream_)
        upstream_->setParent(this);

    connect(client_, &Pipe::bytes, this, [this](const QByteArray &data) {
        snap_.sent += static_cast<quint64>(data.size());
        if (upstream_)
            upstream_->write(data);
        if (upstream_ && client_ && upstream_->backlog() > kHigh)
            client_->pauseRead();
    });
    connect(upstream_, &Pipe::bytes, this, [this](const QByteArray &data) {
        snap_.received += static_cast<quint64>(data.size());
        if (client_)
            client_->write(data);
        if (client_ && upstream_ && client_->backlog() > kHigh)
            upstream_->pauseRead();
    });
    connect(client_, &Pipe::writeDrained, this, [this] {
        if (upstream_ && client_ && client_->backlog() < kLow)
            upstream_->resumeRead();
    });
    connect(upstream_, &Pipe::writeDrained, this, [this] {
        if (upstream_ && client_ && upstream_->backlog() < kLow)
            client_->resumeRead();
    });
    connect(client_, &Pipe::finished, this, [this](const QString &error) { closed(error); });
    connect(upstream_, &Pipe::finished, this, [this](const QString &error) { closed(error); });

    client_->goLive();
    upstream_->goLive();
    snap_.status = QString::fromUtf8("Установлено");
    emit changed();
}

void Flow::haltSockets()
{
    const auto sockets = findChildren<QAbstractSocket *>();
    for (QAbstractSocket *socket : sockets)
        socket->abort();
}

void Flow::stop()
{
    if (closing_)
        return;
    closing_ = true;
    if (client_)
        client_->abort();
    if (upstream_)
        upstream_->abort();
    haltSockets();
    snap_.status = QString::fromUtf8("Закрыто");
    emit changed();
    emit finished();
}

void Flow::closed(const QString &error)
{
    if (closing_)
        return;
    closing_ = true;
    if (client_)
        client_->shutdown();
    if (upstream_)
        upstream_->shutdown();
    snap_.status = error.isEmpty() ? QString::fromUtf8("Закрыто") : QString::fromUtf8("Ошибка");
    if (!error.isEmpty())
        snap_.error = error;
    emit changed();
    emit finished();
}

} // namespace qpr
