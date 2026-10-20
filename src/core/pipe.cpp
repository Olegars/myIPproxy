#include "pipe.h"

#include "shieldcodec.h"

#include <QMetaMethod>
#include <QNetworkProxy>
#include <QSslSocket>
#include <QTimer>

namespace qpr {
namespace {

const qint64 kLowWater = 256 * 1024;

} // namespace

Pipe::Pipe(QObject *parent)
    : QObject(parent)
{
}

void Pipe::hold()
{
    live_ = false;
}

void Pipe::goLive()
{
    live_ = true;
    const bool listening = isSignalConnected(QMetaMethod::fromSignal(&Pipe::bytes));
    if (!early_.isEmpty() && listening) {
        const QByteArray pending = early_;
        early_.clear();
        emit bytes(pending);
    }
}

void Pipe::pushBack(const QByteArray &data)
{
    ingest(data);
}

void Pipe::ingest(const QByteArray &data)
{
    if (data.isEmpty() || finished_)
        return;
    const bool listening = isSignalConnected(QMetaMethod::fromSignal(&Pipe::bytes));
    if (!live_ || !listening) {
        if (early_.size() + data.size() > 4 * 1024 * 1024) {
            finish(QString::fromUtf8("слишком большой буфер"));
            return;
        }
        early_ += data;
        return;
    }
    emit bytes(data);
}

void Pipe::finish(const QString &error)
{
    if (finished_)
        return;
    finished_ = true;
    emit finished(error);
}

SocketPipe::SocketPipe(QTcpSocket *socket, QObject *parent)
    : Pipe(parent)
    , socket_(socket)
{
    socket_->setParent(this);
    socket_->setProxy(QNetworkProxy::NoProxy);
    socket_->setSocketOption(QAbstractSocket::LowDelayOption, 1);
    hook();
}

void SocketPipe::hook()
{
    connect(socket_, &QTcpSocket::readyRead, this, &SocketPipe::onRead);
    connect(socket_, &QTcpSocket::disconnected, this, [this] {
        finish(QString());
    });
    connect(socket_, &QTcpSocket::errorOccurred, this, [this](QAbstractSocket::SocketError error) {
        if (error == QAbstractSocket::RemoteHostClosedError)
            return;
        finish(socket_->errorString());
    });
    connect(socket_, &QTcpSocket::bytesWritten, this, [this](qint64) {
        if (backlog() < kLowWater)
            emit writeDrained();
    });
    if (auto *ssl = qobject_cast<QSslSocket *>(socket_)) {
        connect(ssl, &QSslSocket::encrypted, this, &SocketPipe::onConnected);
    } else {
        connect(socket_, &QTcpSocket::connected, this, &SocketPipe::onConnected);
    }
    if (socket_->state() == QAbstractSocket::ConnectedState)
        markOpen();
    if (socket_->bytesAvailable() > 0)
        QTimer::singleShot(0, this, [this] { onRead(); });
}

void SocketPipe::markOpen()
{
    if (opened_)
        return;
    opened_ = true;
    if (!pendingWrite_.isEmpty() && socket_->state() == QAbstractSocket::ConnectedState) {
        socket_->write(pendingWrite_);
        pendingWrite_.clear();
    }
    QTimer::singleShot(0, this, [this] { emit ready(); });
}

void SocketPipe::connectTo(const QString &host, quint16 port, bool tls, bool insecure)
{
    if (auto *ssl = qobject_cast<QSslSocket *>(socket_)) {
        if (insecure) {
            ssl->setPeerVerifyMode(QSslSocket::VerifyNone);
            ssl->ignoreSslErrors();
        }
        ssl->connectToHostEncrypted(host, port);
        return;
    }
    if (tls) {
        finish(QString::fromUtf8("сокет не поддерживает TLS"));
        return;
    }
    socket_->connectToHost(host, port);
}

void SocketPipe::openExisting()
{
    if (socket_->state() == QAbstractSocket::ConnectedState)
        markOpen();
}

void SocketPipe::onConnected()
{
    markOpen();
}

void SocketPipe::onRead()
{
    if (paused_)
        return;
    ingest(socket_->readAll());
}

void SocketPipe::write(const QByteArray &data)
{
    if (isFinished() || data.isEmpty())
        return;
    if (!opened_ || socket_->state() != QAbstractSocket::ConnectedState) {
        pendingWrite_ += data;
        return;
    }
    socket_->write(data);
}

void SocketPipe::shutdown()
{
    if (!socket_)
        return;
    socket_->disconnectFromHost();
}

void SocketPipe::abort()
{
    if (!socket_)
        return;
    socket_->abort();
    finish(QString());
}

qint64 SocketPipe::backlog() const
{
    return socket_->bytesToWrite() + pendingWrite_.size();
}

void SocketPipe::pauseRead()
{
    paused_ = true;
}

void SocketPipe::resumeRead()
{
    if (!paused_)
        return;
    paused_ = false;
    if (socket_->bytesAvailable() > 0)
        onRead();
}

ShieldPipe::ShieldPipe(Pipe *lower, QObject *parent)
    : Pipe(parent)
    , lower_(lower)
{
    lower_->setParent(this);
    connect(lower_, &Pipe::bytes, this, [this](const QByteArray &data) { onLower(data); });
    connect(lower_, &Pipe::finished, this, [this](const QString &error) { onLowerFinished(error); });
}

void ShieldPipe::startClient(const QString &sni, const QByteArray &key)
{
    client_ = true;
    key_ = key;
    waitingHello_ = true;
    const QString name = sni.trimmed().isEmpty() ? QStringLiteral("ya.ru") : sni.trimmed();
    lower_->write(buildClientHello(name));
}

void ShieldPipe::startServer(const QByteArray &key)
{
    client_ = false;
    key_ = key;
    waitingHello_ = true;
}

void ShieldPipe::write(const QByteArray &data)
{
    if (isFinished() || data.isEmpty())
        return;
    if (!open_ || !authed_) {
        writeQueue_ += data;
        return;
    }
    sealAndWrite(data);
}

void ShieldPipe::shutdown()
{
    lower_->shutdown();
}

void ShieldPipe::abort()
{
    lower_->abort();
    finish(QString());
}

qint64 ShieldPipe::backlog() const
{
    return lower_->backlog() + writeQueue_.size();
}

void ShieldPipe::pauseRead() { lower_->pauseRead(); }
void ShieldPipe::resumeRead() { lower_->resumeRead(); }

void ShieldPipe::onLowerFinished(const QString &error)
{
    finish(error.isEmpty() ? QString::fromUtf8("соединение закрыто") : error);
}

void ShieldPipe::sealAndWrite(const QByteArray &plain)
{
    const int chunk = 16000;
    for (int offset = 0; offset < plain.size(); offset += chunk) {
        QString error;
        const QByteArray record = wrapAppData(key_, plain.mid(offset, chunk), &error);
        if (record.isEmpty()) {
            finish(error);
            return;
        }
        lower_->write(record);
    }
}

void ShieldPipe::becomeOpen()
{
    open_ = true;
    authed_ = true;
    emit ready();
    if (!writeQueue_.isEmpty()) {
        const QByteArray queued = writeQueue_;
        writeQueue_.clear();
        sealAndWrite(queued);
    }
}

void ShieldPipe::onLower(const QByteArray &data)
{
    if (isFinished())
        return;
    if (!recordError_.isEmpty())
        return;
    recordBuf_.append(data);
    while (recordBuf_.size() >= 5 && !isFinished()) {
        const int len = (quint8(recordBuf_.at(3)) << 8) | quint8(recordBuf_.at(4));
        if (len > 20000) {
            finish(QString::fromUtf8("слишком большая TLS-запись"));
            return;
        }
        if (recordBuf_.size() < 5 + len)
            return;
        const quint8 type = quint8(recordBuf_.at(0));
        const QByteArray payload = recordBuf_.mid(5, len);
        recordBuf_.remove(0, 5 + len);
        if (!handleRecord(type, payload))
            return;
    }
}

bool ShieldPipe::handleRecord(quint8 type, const QByteArray &payload)
{
    if (waitingHello_ && !client_) {
        if (type != 22) {
            finish(QString::fromUtf8("ожидался ClientHello"));
            return false;
        }
        QByteArray random;
        const QByteArray hello = buildServerHello(payload, &random);
        serverRandom_ = random;
        lower_->write(hello);
        lower_->write(ccsRecord());
        waitingHello_ = false;
        open_ = true;
        return true;
    }
    if (waitingHello_ && client_) {
        if (type == 20)
            return true;
        if (type != 22) {
            finish(QString::fromUtf8("ожидался ServerHello"));
            return false;
        }
        serverRandom_ = serverRandomFromHandshake(payload);
        if (serverRandom_.size() != 32) {
            finish(QString::fromUtf8("пустой ответ прикрытия"));
            return false;
        }
        waitingHello_ = false;
        lower_->write(ccsRecord());
        QString error;
        const QByteArray auth = wrapAppData(key_, authPrefix(serverRandom_), &error);
        if (auth.isEmpty()) {
            finish(error);
            return false;
        }
        lower_->write(auth);
        becomeOpen();
        return true;
    }
    if (type == 20)
        return true;
    if (type != 23) {
        finish(QString::fromUtf8("неожиданная TLS-запись"));
        return false;
    }
    QString error;
    QByteArray plain;
    if (!unwrapAppData(key_, payload, &plain, &error)) {
        finish(error);
        return false;
    }
    if (!authed_) {
        authBuf_.append(plain);
        if (authBuf_.size() < 36)
            return true;
        if (!authPrefixMatches(authBuf_, serverRandom_)) {
            finish(QString::fromUtf8("прикрытие отклонено: ключ или ответ не совпали"));
            return false;
        }
        const QByteArray rest = authBuf_.mid(36);
        authBuf_.clear();
        becomeOpen();
        if (!rest.isEmpty())
            ingest(rest);
        return true;
    }
    if (!plain.isEmpty())
        ingest(plain);
    return true;
}

FramePipe::FramePipe(Pipe *lower, QObject *parent)
    : Pipe(parent)
    , lower_(lower)
{
    hold();
    lower_->setParent(this);
    connect(lower_, &Pipe::bytes, this, [this](const QByteArray &data) { onLower(data); });
    connect(lower_, &Pipe::finished, this, [this](const QString &error) { onLowerFinished(error); });
    connect(lower_, &Pipe::writeDrained, this, &FramePipe::writeDrained);
}

void FramePipe::sendFrame(quint8 type, const QByteArray &payload)
{
    if (shut_ || isFinished())
        return;
    lower_->write(encodeFrame(type, payload));
}

void FramePipe::write(const QByteArray &data)
{
    if (data.isEmpty())
        return;
    const int chunk = 16000;
    for (int offset = 0; offset < data.size(); offset += chunk)
        sendFrame(FrameData, data.mid(offset, chunk));
}

void FramePipe::shutdown()
{
    if (shut_)
        return;
    shut_ = true;
    sendFrame(FrameClose, {});
    lower_->shutdown();
}

void FramePipe::abort()
{
    shut_ = true;
    lower_->abort();
    finish(QString());
}

qint64 FramePipe::backlog() const
{
    return lower_->backlog();
}

void FramePipe::pauseRead() { lower_->pauseRead(); }
void FramePipe::resumeRead() { lower_->resumeRead(); }

void FramePipe::onLowerFinished(const QString &error)
{
    finish(error);
}

void FramePipe::onLower(const QByteArray &data)
{
    buffer_.append(data);
    QVector<Frame> frames;
    QString error;
    if (!decodeFrames(buffer_, frames, &error)) {
        finish(error);
        return;
    }
    for (const Frame &frame : frames) {
        if (frame.type == FrameData) {
            ingest(frame.payload);
            continue;
        }
        if (frame.type == FrameClose) {
            finish(QString());
            return;
        }
        emit control(frame.type, frame.payload);
    }
}

} // namespace qpr
