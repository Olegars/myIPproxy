#pragma once

#include <QByteArray>
#include <QString>
#include <QVector>

namespace qpr {

constexpr quint8 FrameConnect = 0x01;
constexpr quint8 FrameData = 0x02;
constexpr quint8 FrameClose = 0x03;
constexpr quint8 FrameOk = 0x04;
constexpr quint8 FrameFail = 0x05;
constexpr quint8 FramePing = 0x06;
constexpr quint8 FramePong = 0x07;

struct TlsRecord {
    quint8 type = 0;
    QByteArray payload;
};

struct Frame {
    quint8 type = 0;
    QByteArray payload;
};

QByteArray deriveKey(const QString &psk, QString *error = nullptr);
QByteArray buildClientHello(const QString &sni);
QByteArray buildServerHello(const QByteArray &clientHandshake, QByteArray *randomOut);
QString extractSni(const QByteArray &clientHelloRecord);
QByteArray serverRandomFromHandshake(const QByteArray &handshake);
QByteArray ccsRecord();

class RecordBuffer {
public:
    void append(const QByteArray &bytes);
    bool next(TlsRecord &record);
    bool failed() const { return !error_.isEmpty(); }
    QString error() const { return error_; }
    void clear();

private:
    QByteArray buffer_;
    QString error_;
};

QByteArray wrapAppData(const QByteArray &key, const QByteArray &plain, QString *error = nullptr);
bool unwrapAppData(const QByteArray &key, const QByteArray &recordPayload, QByteArray *plain, QString *error = nullptr);

QByteArray encodeFrame(quint8 type, const QByteArray &payload);
bool decodeFrames(QByteArray &buffer, QVector<Frame> &out, QString *error = nullptr);

QByteArray connectPayload(const QString &host, quint16 port);
bool parseConnectPayload(const QByteArray &payload, QString *host, quint16 *port);

QByteArray authPrefix(const QByteArray &serverRandom);
bool authPrefixMatches(const QByteArray &plain, const QByteArray &serverRandom);

} // namespace qpr
