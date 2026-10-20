#pragma once

#include <QByteArray>
#include <QObject>
#include <QPointer>
#include <QTcpSocket>

namespace qpr {

class Pipe : public QObject {
    Q_OBJECT
public:
    explicit Pipe(QObject *parent = nullptr);

    virtual void write(const QByteArray &data) = 0;
    virtual void shutdown() = 0;
    virtual void abort() = 0;
    virtual qint64 backlog() const = 0;
    virtual void pauseRead() = 0;
    virtual void resumeRead() = 0;

    void hold();
    void goLive();
    void pushBack(const QByteArray &data);

signals:
    void ready();
    void bytes(const QByteArray &data);
    void finished(const QString &error);
    void writeDrained();

protected:
    void ingest(const QByteArray &data);
    void finish(const QString &error);
    bool isFinished() const { return finished_; }
    void markLive(bool live) { live_ = live; }

private:
    bool live_ = true;
    bool finished_ = false;
    QByteArray early_;
};

class SocketPipe : public Pipe {
    Q_OBJECT
public:
    explicit SocketPipe(QTcpSocket *socket, QObject *parent = nullptr);
    void connectTo(const QString &host, quint16 port, bool tls, bool insecure);
    void openExisting();
    QTcpSocket *socket() const { return socket_; }

    void write(const QByteArray &data) override;
    void shutdown() override;
    void abort() override;
    qint64 backlog() const override;
    void pauseRead() override;
    void resumeRead() override;

private:
    void hook();
    void markOpen();
    void onConnected();
    void onRead();

    QTcpSocket *socket_ = nullptr;
    QByteArray pendingWrite_;
    bool paused_ = false;
    bool opened_ = false;
};

class ShieldPipe : public Pipe {
    Q_OBJECT
public:
    explicit ShieldPipe(Pipe *lower, QObject *parent = nullptr);
    void startClient(const QString &sni, const QByteArray &key);
    void startServer(const QByteArray &key);

    void write(const QByteArray &data) override;
    void shutdown() override;
    void abort() override;
    qint64 backlog() const override;
    void pauseRead() override;
    void resumeRead() override;

private:
    void onLower(const QByteArray &data);
    void onLowerFinished(const QString &error);
    bool handleRecord(quint8 type, const QByteArray &payload);
    void sealAndWrite(const QByteArray &plain);
    void becomeOpen();

    Pipe *lower_ = nullptr;
    QByteArray key_;
    QByteArray serverRandom_;
    QByteArray authBuf_;
    QByteArray writeQueue_;
    QByteArray recordBuf_;
    bool client_ = false;
    bool open_ = false;
    bool authed_ = false;
    bool waitingHello_ = false;
    QString recordError_;
};

class FramePipe : public Pipe {
    Q_OBJECT
public:
    explicit FramePipe(Pipe *lower, QObject *parent = nullptr);
    void sendFrame(quint8 type, const QByteArray &payload);

    void write(const QByteArray &data) override;
    void shutdown() override;
    void abort() override;
    qint64 backlog() const override;
    void pauseRead() override;
    void resumeRead() override;

signals:
    void control(quint8 type, const QByteArray &payload);

private:
    void onLower(const QByteArray &data);
    void onLowerFinished(const QString &error);

    Pipe *lower_ = nullptr;
    QByteArray buffer_;
    bool shut_ = false;
};

} // namespace qpr

Q_DECLARE_METATYPE(qpr::Pipe *)
