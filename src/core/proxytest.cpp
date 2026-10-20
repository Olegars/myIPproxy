#include "proxytest.h"

#include "dialer.h"
#include "pipe.h"
#include "shieldcodec.h"

#include <QTcpSocket>
#include <QTimer>

namespace qpr {
namespace {

class Probe : public QObject {
public:
    Probe(QObject *parent, std::function<void(const QString &, bool)> done)
        : QObject(parent)
        , done_(std::move(done))
    {
        timer_.setSingleShot(true);
        timer_.setInterval(12000);
        QObject::connect(&timer_, &QTimer::timeout, this, [this] { finish(QString::fromUtf8("таймаут проверки"), false); });
        timer_.start();
    }

    void finish(const QString &message, bool ok)
    {
        if (finished_)
            return;
        finished_ = true;
        timer_.stop();
        const auto cb = done_;
        deleteLater();
        cb(message, ok);
    }

    QTimer timer_;
    std::function<void(const QString &, bool)> done_;
    bool finished_ = false;
};

void pingShield(const Proxy &proxy, Probe *probe)
{
    QString error;
    const QByteArray key = deriveKey(effectivePsk(proxy), &error);
    if (key.size() != 32) {
        probe->finish(error.isEmpty() ? QString::fromUtf8("для щита нужен общий ключ") : error, false);
        return;
    }
    auto *socket = new SocketPipe(new QTcpSocket, probe);
    auto *shield = new ShieldPipe(socket, probe);
    QObject::connect(socket, &Pipe::finished, probe, [probe](const QString &err) {
        probe->finish(err.isEmpty() ? QString::fromUtf8("TCP закрылся") : err, false);
    });
    QObject::connect(shield, &Pipe::ready, probe, [probe, shield] {
        auto *frame = new FramePipe(shield, probe);
        QObject::connect(frame, &FramePipe::control, probe, [probe](quint8 type, const QByteArray &) {
            if (type == FramePong)
                probe->finish(QString::fromUtf8("щит ответил, прикрытие живое"), true);
        });
        QObject::connect(frame, &Pipe::finished, probe, [probe](const QString &err) {
            probe->finish(err.isEmpty() ? QString::fromUtf8("щит закрыл проверку") : err, false);
        });
        frame->sendFrame(FramePing, {});
    });
    shield->startClient(coverOrDefault(proxy), key);
    socket->connectTo(proxy.host, proxy.port, false, false);
}

void dialTest(const QList<Proxy> &hops, bool remoteDns, Probe *probe, const QString &okText)
{
    auto *dialer = new Dialer(hops, QStringLiteral("1.1.1.1"), 443, remoteDns, probe);
    QObject::connect(dialer, &Dialer::established, probe, [probe, dialer, okText](Pipe *pipe) {
        if (pipe)
            pipe->abort();
        dialer->deleteLater();
        probe->finish(okText, true);
    });
    QObject::connect(dialer, &Dialer::failed, probe, [probe, dialer](const QString &error) {
        dialer->deleteLater();
        probe->finish(error, false);
    });
    dialer->start();
}

} // namespace

void runProxyTest(const Proxy &proxy, QObject *parent, std::function<void(const QString &, bool)> done)
{
    auto *probe = new Probe(parent, std::move(done));
    if (proxy.type == ProxyType::Shield)
        pingShield(proxy, probe);
    else
        dialTest({proxy}, true, probe, QString::fromUtf8("выход до 1.1.1.1:443 открылся"));
}

void runChainTest(const QList<Proxy> &hops, bool remoteDns, QObject *parent,
                  std::function<void(const QString &, bool)> done)
{
    auto *probe = new Probe(parent, std::move(done));
    if (hops.isEmpty()) {
        probe->finish(QString::fromUtf8("в цепочке нет прокси"), false);
        return;
    }
    dialTest(hops, remoteDns, probe, QString::fromUtf8("цепочка открыла 1.1.1.1:443"));
}

} // namespace qpr
