#include "handshakes.h"

#include "shieldcodec.h"
#include "socksutil.h"

namespace qpr {
namespace {

class Step : public QObject {
public:
    Step(Pipe *pipe, std::function<void(const QString &)> done)
        : QObject(pipe)
        , pipe_(pipe)
        , done_(std::move(done))
    {
        connect(pipe_, &Pipe::bytes, this, [this](const QByteArray &data) {
            buffer_.append(data);
            pump();
        });
        connect(pipe_, &Pipe::finished, this, [this](const QString &error) {
            fail(error.isEmpty() ? QString::fromUtf8("соединение закрыто") : error);
        });
    }

protected:
    virtual void pump() = 0;

    void succeed()
    {
        if (finished_)
            return;
        finished_ = true;
        disconnect(pipe_, nullptr, this, nullptr);
        pipe_->hold();
        if (!buffer_.isEmpty())
            pipe_->pushBack(buffer_);
        buffer_.clear();
        const auto cb = done_;
        deleteLater();
        cb(QString());
    }

    void fail(const QString &error)
    {
        if (finished_)
            return;
        finished_ = true;
        disconnect(pipe_, nullptr, this, nullptr);
        const auto cb = done_;
        cb(error);
    }

    Pipe *pipe_ = nullptr;
    QByteArray buffer_;
    bool finished_ = false;
    std::function<void(const QString &)> done_;
};

class Socks5Step : public Step {
public:
    Socks5Step(Pipe *pipe, QString user, QString password, QString host, quint16 port,
               std::function<void(const QString &)> done)
        : Step(pipe, std::move(done))
        , user_(std::move(user))
        , password_(std::move(password))
        , host_(std::move(host))
        , port_(port)
    {
        QByteArray hello;
        hello.append(char(0x05));
        hello.append(char(0x01));
        hello.append(char(user_.isEmpty() ? 0x00 : 0x02));
        pipe_->write(hello);
    }

protected:
    void pump() override
    {
        if (stage_ == 0) {
            if (buffer_.size() < 2)
                return;
            if (quint8(buffer_.at(0)) != 0x05) {
                fail(QString::fromUtf8("прокси не говорит на SOCKS5"));
                return;
            }
            const quint8 method = quint8(buffer_.at(1));
            buffer_.remove(0, 2);
            if (method == 0xFF) {
                fail(QString::fromUtf8("SOCKS5 не принял метод авторизации"));
                return;
            }
            if (method == 0x02) {
                QByteArray user = user_.toUtf8().left(255);
                QByteArray pass = password_.toUtf8().left(255);
                QByteArray auth;
                auth.append(char(0x01));
                auth.append(char(user.size()));
                auth.append(user);
                auth.append(char(pass.size()));
                auth.append(pass);
                pipe_->write(auth);
                stage_ = 1;
            } else if (method == 0x00) {
                pipe_->write(socks5ConnectRequest(host_, port_));
                stage_ = 2;
            } else {
                fail(QString::fromUtf8("SOCKS5 выбрал неподдерживаемый метод"));
                return;
            }
            if (!buffer_.isEmpty())
                pump();
            return;
        }
        if (stage_ == 1) {
            if (buffer_.size() < 2)
                return;
            if (quint8(buffer_.at(1)) != 0x00) {
                fail(QString::fromUtf8("SOCKS5 отклонил логин или пароль"));
                return;
            }
            buffer_.remove(0, 2);
            pipe_->write(socks5ConnectRequest(host_, port_));
            stage_ = 2;
            if (!buffer_.isEmpty())
                pump();
            return;
        }
        QString error;
        Socks5Reply reply;
        int consumed = 0;
        const ParseStatus status = parseSocks5Reply(buffer_, &consumed, &reply, &error);
        if (status == ParseStatus::NeedMore)
            return;
        if (status == ParseStatus::Bad) {
            fail(error);
            return;
        }
        buffer_.remove(0, consumed);
        if (reply.rep != 0x00) {
            fail(error.isEmpty() ? socks5RepText(reply.rep) : error);
            return;
        }
        succeed();
    }

private:
    QString user_;
    QString password_;
    QString host_;
    quint16 port_ = 0;
    int stage_ = 0;
};

class Socks4Step : public Step {
public:
    Socks4Step(Pipe *pipe, QString host, quint16 port, bool domainName, std::function<void(const QString &)> done)
        : Step(pipe, std::move(done))
    {
        pipe_->write(socks4ConnectRequest(host, port, domainName));
    }

protected:
    void pump() override
    {
        int consumed = 0;
        bool ok = false;
        QString error;
        const ParseStatus status = parseSocks4Reply(buffer_, &consumed, &ok, &error);
        if (status == ParseStatus::NeedMore)
            return;
        buffer_.remove(0, consumed);
        if (!ok) {
            fail(error);
            return;
        }
        succeed();
    }
};

class HttpStep : public Step {
public:
    HttpStep(Pipe *pipe, QString user, QString password, QString host, quint16 port,
             std::function<void(const QString &)> done)
        : Step(pipe, std::move(done))
    {
        QString request = QString::fromUtf8("CONNECT %1:%2 HTTP/1.1\r\nHost: %1:%2\r\nProxy-Connection: keep-alive\r\n")
                              .arg(host)
                              .arg(port);
        if (!user.isEmpty()) {
            const QByteArray token = (user + QLatin1Char(':') + password).toUtf8().toBase64();
            request += QString::fromUtf8("Proxy-Authorization: Basic %1\r\n")
                           .arg(QString::fromLatin1(token));
        }
        request += QString::fromUtf8("\r\n");
        pipe_->write(request.toUtf8());
    }

protected:
    void pump() override
    {
        const int end = buffer_.indexOf(QByteArrayLiteral("\r\n\r\n"));
        if (end < 0) {
            if (buffer_.size() > 64 * 1024)
                fail(QString::fromUtf8("слишком длинный ответ HTTP-прокси"));
            return;
        }
        const QByteArray head = buffer_.left(end);
        buffer_.remove(0, end + 4);
        const int lineEnd = head.indexOf(QByteArrayLiteral("\r\n"));
        const QByteArray line = lineEnd >= 0 ? head.left(lineEnd) : head;
        const int codeStart = line.indexOf(' ');
        int code = 0;
        if (codeStart >= 0)
            code = line.mid(codeStart + 1).left(3).toInt();
        if (code < 200 || code >= 300) {
            fail(QString::fromUtf8("HTTP-прокси вернул %1").arg(QString::fromLatin1(line)));
            return;
        }
        succeed();
    }
};

} // namespace

void handshakeSocks5(Pipe *pipe, const QString &user, const QString &password,
                     const QString &host, quint16 port,
                     std::function<void(const QString &error)> done)
{
    new Socks5Step(pipe, user, password, host, port, std::move(done));
}

void handshakeSocks4(Pipe *pipe, const QString &host, quint16 port, bool domainName,
                     std::function<void(const QString &error)> done)
{
    new Socks4Step(pipe, host, port, domainName, std::move(done));
}

void handshakeHttp(Pipe *pipe, const QString &user, const QString &password,
                   const QString &host, quint16 port,
                   std::function<void(const QString &error)> done)
{
    new HttpStep(pipe, user, password, host, port, std::move(done));
}

class ShieldWaiter : public QObject {
public:
    ShieldWaiter(FramePipe *frame, std::function<void(Pipe *, const QString &)> done)
        : QObject(frame)
        , frame_(frame)
        , done_(std::move(done))
    {
        connect(frame_, &FramePipe::control, this, [this](quint8 type, const QByteArray &payload) {
            if (type == FrameOk)
                finish(frame_, {});
            else if (type == FrameFail || type == FrameClose) {
                const QString error = payload.isEmpty()
                    ? QString::fromUtf8("удалённый щит отклонил соединение")
                    : QString::fromUtf8(payload);
                finish(nullptr, error);
            }
        });
        connect(frame_, &Pipe::finished, this, [this](const QString &error) {
            finish(nullptr, error.isEmpty() ? QString::fromUtf8("щит закрыл соединение") : error);
        });
    }

private:
    void finish(Pipe *out, const QString &error)
    {
        if (once_)
            return;
        once_ = true;
        disconnect(frame_, nullptr, this, nullptr);
        const auto cb = done_;
        deleteLater();
        cb(out, error);
    }

    FramePipe *frame_ = nullptr;
    std::function<void(Pipe *, const QString &)> done_;
    bool once_ = false;
};

void handshakeShield(Pipe *pipe, const QString &host, quint16 port,
                     std::function<void(Pipe *stream, const QString &error)> done)
{
    auto *frame = new FramePipe(pipe, pipe->parent());
    new ShieldWaiter(frame, std::move(done));
    frame->sendFrame(FrameConnect, connectPayload(host, port));
}

} // namespace qpr
