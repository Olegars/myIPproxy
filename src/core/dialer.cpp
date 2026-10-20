#include "dialer.h"

#include "cidr.h"
#include "dnscache.h"
#include "handshakes.h"
#include "logger.h"
#include "shieldcodec.h"

#include <QSslSocket>

namespace qpr {

Dialer::Dialer(QList<Proxy> hops, QString host, quint16 port, bool remoteDns, QObject *parent)
    : QObject(parent)
    , hops_(std::move(hops))
    , host_(std::move(host))
    , port_(port)
    , remoteDns_(remoteDns)
{
    timer_.setSingleShot(true);
    timer_.setInterval(20000);
    connect(&timer_, &QTimer::timeout, this, [this] {
        fail(QString::fromUtf8("таймаут соединения"));
    });
}

void Dialer::start()
{
    if (host_.trimmed().isEmpty() || port_ == 0) {
        fail(QString::fromUtf8("пустой адрес назначения"));
        return;
    }
    timer_.start();
    if (hops_.isEmpty()) {
        auto *pipe = new SocketPipe(new QTcpSocket, this);
        watch(pipe);
        connect(pipe, &Pipe::ready, this, [this, pipe] { succeed(pipe); });
        pipe->connectTo(host_, port_, false, false);
        return;
    }
    const Proxy &first = hops_.first();
    if (first.host.trimmed().isEmpty() || first.port == 0) {
        fail(QString::fromUtf8("у прокси не задан адрес"));
        return;
    }
    if (first.type == ProxyType::Https && transportIsShield(first)) {
        fail(QString::fromUtf8("HTTPS-прокси нельзя оборачивать в щит"));
        return;
    }
    if (first.type == ProxyType::Https && !QSslSocket::supportsSsl()) {
        fail(QString::fromUtf8("Qt собран без SSL, HTTPS-прокси недоступен"));
        return;
    }
    if (transportIsShield(first) && effectivePsk(first).isEmpty()) {
        fail(QString::fromUtf8("для щита нужен общий ключ"));
        return;
    }
    QTcpSocket *raw = first.type == ProxyType::Https ? static_cast<QTcpSocket *>(new QSslSocket) : new QTcpSocket;
    auto *pipe = new SocketPipe(raw, this);
    watch(pipe);
    connect(pipe, &Pipe::ready, this, [this, pipe] { begin(0, pipe); });
    Logger::instance()->info(QString::fromUtf8("TCP к %1:%2").arg(first.host).arg(first.port));
    pipe->connectTo(first.host, first.port, first.type == ProxyType::Https, first.tlsInsecure);
}

void Dialer::fail(const QString &error)
{
    if (done_)
        return;
    done_ = true;
    timer_.stop();
    emit failed(error);
}

void Dialer::succeed(Pipe *pipe)
{
    if (done_ || !pipe)
        return;
    done_ = true;
    timer_.stop();
    if (watch_)
        disconnect(watch_);
    pipe->hold();
    pipe->setParent(nullptr);
    emit established(pipe);
}

void Dialer::watch(Pipe *pipe)
{
    if (watch_)
        disconnect(watch_);
    watch_ = connect(pipe, &Pipe::finished, this, [this](const QString &error) {
        fail(error.isEmpty() ? QString::fromUtf8("соединение закрыто") : error);
    });
}

void Dialer::nextTarget(int index, QString *host, quint16 *port) const
{
    if (index + 1 < hops_.size()) {
        *host = hops_.at(index + 1).host;
        *port = hops_.at(index + 1).port;
    } else {
        *host = host_;
        *port = port_;
    }
}

void Dialer::begin(int index, Pipe *pipe)
{
    if (done_)
        return;
    if (index < 0 || index >= hops_.size()) {
        fail(QString::fromUtf8("пустой прыжок цепочки"));
        return;
    }
    const Proxy hop = hops_.at(index);
    if (index > 0 && hop.type == ProxyType::Https) {
        fail(QString::fromUtf8("HTTPS-прокси может быть только первым в цепочке"));
        return;
    }
    if (transportIsShield(hop)) {
        if (hop.type == ProxyType::Https) {
            fail(QString::fromUtf8("HTTPS-прокси нельзя оборачивать в щит"));
            return;
        }
        QString error;
        const QByteArray key = deriveKey(effectivePsk(hop), &error);
        if (key.size() != 32) {
            fail(error.isEmpty() ? QString::fromUtf8("для щита нужен общий ключ") : error);
            return;
        }
        if (hop.host.compare(coverOrDefault(hop), Qt::CaseInsensitive) == 0) {
            Logger::instance()->warn(QString::fromUtf8(
                "Адрес прокси совпадает с именем прикрытия. TCP всё равно идёт на этот адрес, а не «мимо» него."));
        }
        auto *shield = new ShieldPipe(pipe, this);
        watch(shield);
        connect(shield, &Pipe::ready, this, [this, shield, hop, index] {
            runInner(shield, hop, index);
        });
        connect(shield, &Pipe::finished, this, [this](const QString &error) {
            fail(error.isEmpty() ? QString::fromUtf8("щит закрыл соединение") : error);
        });
        Logger::instance()->info(QString::fromUtf8("Прикрытие SNI %1, адрес назначения %2:%3")
                                     .arg(coverOrDefault(hop), hop.host)
                                     .arg(hop.port));
        shield->startClient(coverOrDefault(hop), key);
        return;
    }
    runInner(pipe, hop, index);
}

void Dialer::runInner(Pipe *transport, const Proxy &hop, int index)
{
    QString host;
    quint16 port = 0;
    nextTarget(index, &host, &port);
    const bool passName = remoteDns_ && hop.type != ProxyType::Socks4;
    if (!passName && !isIpAddress(host)) {
        DnsCache::instance()->resolve(host, this, [this, transport, hop, index, port](QHostAddress address, QString error) {
            if (done_)
                return;
            if (!error.isEmpty() || address.isNull()) {
                fail(error.isEmpty() ? QString::fromUtf8("не удалось резолвить адрес") : error);
                return;
            }
            startInner(transport, hop, index, address.toString(), port);
        });
        return;
    }
    startInner(transport, hop, index, host, port);
}

void Dialer::startInner(Pipe *transport, const Proxy &hop, int index, const QString &host, quint16 port)
{
    if (done_)
        return;
    auto cont = [this, index](Pipe *out, const QString &error) {
        if (done_)
            return;
        if (!error.isEmpty() || !out) {
            fail(error.isEmpty() ? QString::fromUtf8("прокси не открыл соединение") : error);
            return;
        }
        if (index + 1 >= hops_.size())
            succeed(out);
        else
            begin(index + 1, out);
    };
    if (hop.type == ProxyType::Shield) {
        handshakeShield(transport, host, port, cont);
        return;
    }
    auto plain = [cont, transport](const QString &error) {
        cont(error.isEmpty() ? transport : nullptr, error);
    };
    switch (hop.type) {
    case ProxyType::Socks5:
        handshakeSocks5(transport, hop.user, hop.password, host, port, plain);
        break;
    case ProxyType::Socks4:
        handshakeSocks4(transport, host, port, false, plain);
        break;
    case ProxyType::Socks4a:
        handshakeSocks4(transport, host, port, !isIpAddress(host), plain);
        break;
    case ProxyType::Http:
    case ProxyType::Https:
        handshakeHttp(transport, hop.user, hop.password, host, port, plain);
        break;
    case ProxyType::Shield:
        break;
    }
}

} // namespace qpr
