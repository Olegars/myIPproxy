#include "shieldserver.h"

#include "logger.h"
#include "pipe.h"
#include "shieldcodec.h"
#include "socksutil.h"

#include <QTcpServer>
#include <QTcpSocket>
#include <QUrl>

namespace qpr {
namespace {

class Exit : public QObject {
public:
    Exit(QTcpSocket *socket, const QByteArray &key, QObject *parent)
        : QObject(parent)
    {
        auto *raw = new SocketPipe(socket, this);
        shield_ = new ShieldPipe(raw, this);
        connect(shield_, &Pipe::ready, this, [this] { arm(); });
        connect(shield_, &Pipe::finished, this, [this](const QString &) { deleteLater(); });
        shield_->startServer(key);
    }

private:
    enum class Mode { Unknown, Frames, Socks, Http };

    void arm()
    {
        connect(shield_, &Pipe::bytes, this, [this](const QByteArray &data) { onPlain(data); });
        shield_->goLive();
    }

    void onPlain(const QByteArray &data)
    {
        if (mode_ == Mode::Unknown && !data.isEmpty()) {
            const quint8 kind = quint8(data.at(0));
            if (kind == 0x05)
                mode_ = Mode::Socks;
            else if (kind >= 'A' && kind <= 'Z')
                mode_ = Mode::Http;
            else
                mode_ = Mode::Frames;
        }
        buffer_.append(data);
        if (mode_ == Mode::Frames)
            pumpFrames();
        else if (mode_ == Mode::Socks)
            pumpSocks();
        else if (mode_ == Mode::Http)
            pumpHttp();
    }

    void pumpFrames()
    {
        QVector<Frame> frames;
        QString error;
        if (!decodeFrames(buffer_, frames, &error)) {
            shield_->abort();
            return;
        }
        for (const Frame &frame : frames) {
            if (frame.type == FramePing) {
                shield_->write(encodeFrame(FramePong, {}));
            } else if (frame.type == FrameConnect) {
                QString host;
                quint16 port = 0;
                if (!parseConnectPayload(frame.payload, &host, &port)) {
                    shield_->write(encodeFrame(FrameFail, QString::fromUtf8("плохой адрес").toUtf8()));
                    continue;
                }
                dial(host, port, true);
            } else if (frame.type == FrameData) {
                if (upstream_)
                    upstream_->write(frame.payload);
                else
                    early_ += frame.payload;
            } else if (frame.type == FrameClose) {
                shield_->shutdown();
            }
        }
    }

    void pumpSocks()
    {
        if (socksStage_ == 0) {
            if (buffer_.size() < 2)
                return;
            const int n = quint8(buffer_.at(1));
            if (buffer_.size() < 2 + n)
                return;
            buffer_.remove(0, 2 + n);
            shield_->write(socks5MethodReply(0x00));
            socksStage_ = 1;
        }
        if (socksStage_ == 1) {
            if (buffer_.size() < 4)
                return;
            int consumed = 0;
            Socks5Reply request;
            QString error;
            const ParseStatus status = parseSocks5Reply(buffer_, &consumed, &request, &error);
            if (status == ParseStatus::NeedMore)
                return;
            if (status == ParseStatus::Bad || request.rep != 0x01) {
                shield_->write(socks5ServerReply(0x07, {}, 0));
                shield_->abort();
                return;
            }
            buffer_.remove(0, consumed);
            early_ += buffer_;
            buffer_.clear();
            socksStage_ = 2;
            dial(request.host, request.port, false);
        }
    }

    void pumpHttp()
    {
        const int end = buffer_.indexOf(QByteArrayLiteral("\r\n\r\n"));
        if (end < 0)
            return;
        const QByteArray head = buffer_.left(end);
        const QByteArray rest = buffer_.mid(end + 4);
        buffer_.clear();
        const QByteArray start = head.left(head.indexOf(QByteArrayLiteral("\r\n")));
        const QList<QByteArray> parts = start.split(' ');
        if (parts.size() < 2 || parts.at(0).toUpper() != QByteArrayLiteral("CONNECT")) {
            shield_->write(QByteArrayLiteral("HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n"));
            shield_->abort();
            return;
        }
        const QByteArray spec = parts.at(1);
        const int colon = spec.lastIndexOf(':');
        const QString host = QString::fromUtf8(colon > 0 ? spec.left(colon) : spec);
        const quint16 port = colon > 0 ? spec.mid(colon + 1).toUShort() : 443;
        early_ += rest;
        httpConnect_ = true;
        dial(host, port, false);
    }

    void dial(const QString &host, quint16 port, bool framed)
    {
        if (dialing_)
            return;
        dialing_ = true;
        framed_ = framed;
        auto *upstream = new SocketPipe(new QTcpSocket, this);
        connect(upstream, &Pipe::ready, this, [this, upstream] {
            upstream_ = upstream;
            if (framed_)
                shield_->write(encodeFrame(FrameOk, {}));
            else if (httpConnect_)
                shield_->write(QByteArrayLiteral("HTTP/1.1 200 Connection Established\r\n\r\n"));
            else
                shield_->write(socks5ServerReply(0x00, {}, 0));
            connect(upstream_, &Pipe::bytes, this, [this](const QByteArray &data) {
                if (framed_)
                    shield_->write(encodeFrame(FrameData, data));
                else
                    shield_->write(data);
            });
            upstream_->goLive();
            if (!early_.isEmpty()) {
                upstream_->write(early_);
                early_.clear();
            }
        });
        connect(upstream, &Pipe::finished, this, [this](const QString &error) {
            if (!upstream_) {
                const QByteArray why = error.toUtf8();
                if (framed_)
                    shield_->write(encodeFrame(FrameFail, why));
                else if (httpConnect_)
                    shield_->write(QByteArrayLiteral("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n"));
                else
                    shield_->write(socks5ServerReply(0x05, {}, 0));
            }
            shield_->shutdown();
        });
        Logger::instance()->info(QString::fromUtf8("Щит открывает %1:%2").arg(host).arg(port));
        upstream->connectTo(host, port, false, false);
    }

    ShieldPipe *shield_ = nullptr;
    SocketPipe *upstream_ = nullptr;
    Mode mode_ = Mode::Unknown;
    QByteArray buffer_;
    QByteArray early_;
    bool dialing_ = false;
    bool framed_ = false;
    bool httpConnect_ = false;
    int socksStage_ = 0;
};

} // namespace

ShieldServer::ShieldServer(QObject *parent)
    : QObject(parent)
{
}

void ShieldServer::setPsk(const QString &psk)
{
    psk_ = psk;
}

bool ShieldServer::listen(const QHostAddress &address, quint16 port)
{
    if (!server_)
        server_ = new QTcpServer(this);
    else
        server_->close();
    connect(server_, &QTcpServer::newConnection, this, &ShieldServer::accept, Qt::UniqueConnection);
    if (!server_->listen(address, port)) {
        Logger::instance()->error(QString::fromUtf8("Щит не слушает %1:%2 — %3")
                                     .arg(address.toString())
                                     .arg(port)
                                     .arg(server_->errorString()));
        return false;
    }
    Logger::instance()->info(QString::fromUtf8("Щит слушает %1:%2").arg(address.toString()).arg(server_->serverPort()));
    return true;
}

void ShieldServer::closeListener()
{
    if (server_)
        server_->close();
}

quint16 ShieldServer::port() const
{
    return server_ && server_->isListening() ? server_->serverPort() : 0;
}

bool ShieldServer::listening() const
{
    return server_ && server_->isListening();
}

void ShieldServer::accept()
{
    QString error;
    const QByteArray key = deriveKey(psk_, &error);
    while (server_ && server_->hasPendingConnections()) {
        auto *socket = server_->nextPendingConnection();
        if (key.size() != 32) {
            Logger::instance()->error(error.isEmpty() ? QString::fromUtf8("у щита не задан ключ") : error);
            socket->abort();
            socket->deleteLater();
            continue;
        }
        new Exit(socket, key, this);
    }
}

} // namespace qpr
