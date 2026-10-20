#include "socksutil.h"

#include "cidr.h"

#include <cstring>

namespace qpr {
namespace {

void appendU8(QByteArray &out, quint8 value)
{
    out.append(static_cast<char>(value));
}

void appendU16(QByteArray &out, quint16 value)
{
    out.append(static_cast<char>((value >> 8) & 0xff));
    out.append(static_cast<char>(value & 0xff));
}

quint16 readU16(const QByteArray &buf, int offset)
{
    return (quint16(quint8(buf.at(offset))) << 8) | quint16(quint8(buf.at(offset + 1)));
}

void appendAddress(QByteArray &out, const QString &host, quint16 port)
{
    QHostAddress addr;
    if (addr.setAddress(host) && addr.protocol() == QAbstractSocket::IPv4Protocol) {
        appendU8(out, 0x01);
        const quint32 ip = addr.toIPv4Address();
        appendU8(out, static_cast<quint8>((ip >> 24) & 0xff));
        appendU8(out, static_cast<quint8>((ip >> 16) & 0xff));
        appendU8(out, static_cast<quint8>((ip >> 8) & 0xff));
        appendU8(out, static_cast<quint8>(ip & 0xff));
    } else if (addr.setAddress(host) && addr.protocol() == QAbstractSocket::IPv6Protocol
               && addr.toIPv4Address() == 0) {
        appendU8(out, 0x04);
        Q_IPV6ADDR v6 = addr.toIPv6Address();
        out.append(reinterpret_cast<const char *>(v6.c), 16);
    } else {
        const QByteArray name = host.toUtf8();
        appendU8(out, 0x03);
        appendU8(out, static_cast<quint8>(qMin(name.size(), 255)));
        out.append(name.left(255));
    }
    appendU16(out, port);
}

int addressLength(const QByteArray &buffer, int atypOffset, QString *error)
{
    if (buffer.size() <= atypOffset) {
        if (error)
            error->clear();
        return -1;
    }
    const quint8 atyp = quint8(buffer.at(atypOffset));
    if (atyp == 0x01)
        return 4;
    if (atyp == 0x04)
        return 16;
    if (atyp == 0x03) {
        if (buffer.size() < atypOffset + 2)
            return -1;
        return 1 + quint8(buffer.at(atypOffset + 1));
    }
    if (error)
        *error = QString::fromUtf8("неизвестный тип адреса");
    return -2;
}

bool readAddress(const QByteArray &buffer, int offset, int addrLen, quint8 atyp, QString *host, quint16 *port)
{
    int cursor = offset;
    QString text;
    if (atyp == 0x01) {
        const quint32 ip = (quint32(quint8(buffer.at(cursor))) << 24)
            | (quint32(quint8(buffer.at(cursor + 1))) << 16)
            | (quint32(quint8(buffer.at(cursor + 2))) << 8)
            | quint32(quint8(buffer.at(cursor + 3)));
        text = QHostAddress(ip).toString();
        cursor += 4;
    } else if (atyp == 0x04) {
        Q_IPV6ADDR v6{};
        memcpy(v6.c, buffer.constData() + cursor, 16);
        text = QHostAddress(v6).toString();
        cursor += 16;
    } else if (atyp == 0x03) {
        const int len = quint8(buffer.at(cursor));
        text = QString::fromUtf8(buffer.mid(cursor + 1, len));
        cursor += 1 + len;
    } else {
        return false;
    }
    if (buffer.size() < cursor + 2)
        return false;
    if (host)
        *host = text;
    if (port)
        *port = readU16(buffer, cursor);
    Q_UNUSED(addrLen);
    return true;
}

} // namespace

QByteArray socks5ConnectRequest(const QString &host, quint16 port)
{
    QByteArray out;
    appendU8(out, 0x05);
    appendU8(out, 0x01);
    appendU8(out, 0x00);
    appendAddress(out, host, port);
    return out;
}

QByteArray socks5UdpAssociateRequest()
{
    QByteArray out;
    appendU8(out, 0x05);
    appendU8(out, 0x03);
    appendU8(out, 0x00);
    appendU8(out, 0x01);
    out.append(QByteArray(4, 0));
    appendU16(out, 0);
    return out;
}

ParseStatus parseSocks5Reply(const QByteArray &buffer, int *consumed, Socks5Reply *reply, QString *error)
{
    if (buffer.size() < 4)
        return ParseStatus::NeedMore;
    if (quint8(buffer.at(0)) != 0x05) {
        if (error)
            *error = QString::fromUtf8("это не ответ SOCKS5");
        return ParseStatus::Bad;
    }
    QString addrError;
    const int addrLen = addressLength(buffer, 3, &addrError);
    if (addrLen == -2) {
        if (error)
            *error = addrError;
        return ParseStatus::Bad;
    }
    if (addrLen < 0)
        return ParseStatus::NeedMore;
    const int total = 4 + addrLen + 2;
    if (buffer.size() < total)
        return ParseStatus::NeedMore;
    Socks5Reply parsed;
    parsed.rep = quint8(buffer.at(1));
    const quint8 atyp = quint8(buffer.at(3));
    if (!readAddress(buffer, 4, addrLen, atyp, &parsed.host, &parsed.port)) {
        if (error)
            *error = QString::fromUtf8("не разобрать адрес в ответе SOCKS5");
        return ParseStatus::Bad;
    }
    if (consumed)
        *consumed = total;
    if (reply)
        *reply = parsed;
    if (parsed.rep != 0x00) {
        if (error)
            *error = socks5RepText(parsed.rep);
        return ParseStatus::Ok;
    }
    if (error)
        error->clear();
    return ParseStatus::Ok;
}

QByteArray socks4ConnectRequest(const QString &host, quint16 port, bool domainName)
{
    QByteArray out;
    appendU8(out, 0x04);
    appendU8(out, 0x01);
    appendU16(out, port);
    if (domainName) {
        out.append(char(0));
        out.append(char(0));
        out.append(char(0));
        out.append(char(1));
        appendU8(out, 0);
        out.append(host.toUtf8());
        appendU8(out, 0);
    } else {
        QHostAddress addr(host);
        const quint32 ip = addr.toIPv4Address();
        appendU8(out, static_cast<quint8>((ip >> 24) & 0xff));
        appendU8(out, static_cast<quint8>((ip >> 16) & 0xff));
        appendU8(out, static_cast<quint8>((ip >> 8) & 0xff));
        appendU8(out, static_cast<quint8>(ip & 0xff));
        appendU8(out, 0);
    }
    return out;
}

ParseStatus parseSocks4Reply(const QByteArray &buffer, int *consumed, bool *ok, QString *error)
{
    if (buffer.size() < 8)
        return ParseStatus::NeedMore;
    const quint8 code = quint8(buffer.at(1));
    if (consumed)
        *consumed = 8;
    const bool success = code == 0x5a;
    if (ok)
        *ok = success;
    if (!success && error)
        *error = QString::fromUtf8("SOCKS4 отклонён (%1)").arg(code);
    return ParseStatus::Ok;
}

QByteArray socks5ServerReply(quint8 rep, const QHostAddress &bindAddr, quint16 bindPort)
{
    QByteArray out;
    appendU8(out, 0x05);
    appendU8(out, rep);
    appendU8(out, 0x00);
    QHostAddress addr = bindAddr;
    if (addr.protocol() != QAbstractSocket::IPv4Protocol)
        addr = QHostAddress(QStringLiteral("0.0.0.0"));
    appendAddress(out, addr.toString(), bindPort);
    return out;
}

QByteArray socks5MethodReply(quint8 method)
{
    QByteArray out;
    appendU8(out, 0x05);
    appendU8(out, method);
    return out;
}

QByteArray socksUdpPacket(const QString &host, quint16 port, const QByteArray &payload)
{
    QByteArray out;
    appendU16(out, 0);
    appendU8(out, 0);
    appendAddress(out, host, port);
    out.append(payload);
    return out;
}

ParseStatus parseSocksUdpPacket(const QByteArray &packet, QString *host, quint16 *port, QByteArray *payload, QString *error)
{
    if (packet.size() < 4)
        return ParseStatus::NeedMore;
    if (quint8(packet.at(2)) != 0) {
        if (error)
            *error = QString::fromUtf8("фрагментированный UDP не поддерживается");
        return ParseStatus::Bad;
    }
    QString addrError;
    const int addrLen = addressLength(packet, 3, &addrError);
    if (addrLen == -2) {
        if (error)
            *error = addrError;
        return ParseStatus::Bad;
    }
    if (addrLen < 0 || packet.size() < 4 + addrLen + 2)
        return ParseStatus::NeedMore;
    const quint8 atyp = quint8(packet.at(3));
    if (!readAddress(packet, 4, addrLen, atyp, host, port)) {
        if (error)
            *error = QString::fromUtf8("не разобрать UDP-заголовок SOCKS");
        return ParseStatus::Bad;
    }
    const int header = 4 + addrLen + 2;
    if (payload)
        *payload = packet.mid(header);
    return ParseStatus::Ok;
}

QString socks5RepText(quint8 rep)
{
    switch (rep) {
    case 0x00: return QString::fromUtf8("успех");
    case 0x01: return QString::fromUtf8("общая ошибка SOCKS");
    case 0x02: return QString::fromUtf8("запрещено правилами");
    case 0x03: return QString::fromUtf8("сеть недоступна");
    case 0x04: return QString::fromUtf8("хост недоступен");
    case 0x05: return QString::fromUtf8("соединение отклонено");
    case 0x06: return QString::fromUtf8("TTL истёк");
    case 0x07: return QString::fromUtf8("команда не поддерживается");
    case 0x08: return QString::fromUtf8("тип адреса не поддерживается");
    default: return QString::fromUtf8("ошибка SOCKS %1").arg(rep);
    }
}

} // namespace qpr
