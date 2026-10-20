#include "cidr.h"

namespace qpr {

bool isIpAddress(const QString &text)
{
    QHostAddress addr;
    return addr.setAddress(text.trimmed());
}

bool cidrContains(const QString &cidr, const QHostAddress &ip)
{
    const QString spec = cidr.trimmed();
    const int slash = spec.indexOf(QLatin1Char('/'));
    if (slash <= 0 || ip.protocol() != QAbstractSocket::IPv4Protocol)
        return false;
    QHostAddress base;
    if (!base.setAddress(spec.left(slash).trimmed()))
        return false;
    if (base.protocol() != QAbstractSocket::IPv4Protocol)
        return false;
    bool ok = false;
    const int bits = spec.mid(slash + 1).trimmed().toInt(&ok);
    if (!ok || bits < 0 || bits > 32)
        return false;
    const quint32 mask = bits == 0 ? 0u : (0xFFFFFFFFu << (32 - bits));
    return (ip.toIPv4Address() & mask) == (base.toIPv4Address() & mask);
}

bool portsMatch(const QString &spec, quint16 port)
{
    const QString trimmed = spec.trimmed();
    if (trimmed.isEmpty() || trimmed == QLatin1String("*"))
        return true;
    const QStringList parts = trimmed.split(QLatin1Char(','), Qt::SkipEmptyParts);
    for (QString part : parts) {
        part = part.trimmed();
        const int dash = part.indexOf(QLatin1Char('-'));
        if (dash > 0) {
            bool okLo = false;
            bool okHi = false;
            const int lo = part.left(dash).trimmed().toInt(&okLo);
            const int hi = part.mid(dash + 1).trimmed().toInt(&okHi);
            if (okLo && okHi && port >= lo && port <= hi)
                return true;
        } else {
            bool ok = false;
            const int value = part.toInt(&ok);
            if (ok && value == int(port))
                return true;
        }
    }
    return false;
}

bool portsSpecValid(const QString &spec)
{
    const QString trimmed = spec.trimmed();
    if (trimmed.isEmpty() || trimmed == QLatin1String("*"))
        return true;
    const QStringList parts = trimmed.split(QLatin1Char(','), Qt::SkipEmptyParts);
    if (parts.isEmpty())
        return false;
    for (QString part : parts) {
        part = part.trimmed();
        const int dash = part.indexOf(QLatin1Char('-'));
        auto validPort = [](const QString &text, int *out) {
            bool ok = false;
            const int value = text.trimmed().toInt(&ok);
            if (!ok || value < 1 || value > 65535)
                return false;
            *out = value;
            return true;
        };
        if (dash > 0) {
            int lo = 0;
            int hi = 0;
            if (!validPort(part.left(dash), &lo) || !validPort(part.mid(dash + 1), &hi) || lo > hi)
                return false;
        } else {
            int value = 0;
            if (!validPort(part, &value))
                return false;
        }
    }
    return true;
}

} // namespace qpr
