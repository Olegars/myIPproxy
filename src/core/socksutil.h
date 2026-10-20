#pragma once

#include <QByteArray>
#include <QHostAddress>
#include <QString>

namespace qpr {

enum class ParseStatus { NeedMore, Ok, Bad };

struct Socks5Reply {
    quint8 rep = 0xff;
    QString host;
    quint16 port = 0;
};

QByteArray socks5ConnectRequest(const QString &host, quint16 port);
QByteArray socks5UdpAssociateRequest();
ParseStatus parseSocks5Reply(const QByteArray &buffer, int *consumed, Socks5Reply *reply, QString *error);

QByteArray socks4ConnectRequest(const QString &host, quint16 port, bool domainName);
ParseStatus parseSocks4Reply(const QByteArray &buffer, int *consumed, bool *ok, QString *error);

QByteArray socks5ServerReply(quint8 rep, const QHostAddress &bindAddr, quint16 bindPort);
QByteArray socks5MethodReply(quint8 method);

QByteArray socksUdpPacket(const QString &host, quint16 port, const QByteArray &payload);
ParseStatus parseSocksUdpPacket(const QByteArray &packet, QString *host, quint16 *port, QByteArray *payload, QString *error);

QString socks5RepText(quint8 rep);

} // namespace qpr
