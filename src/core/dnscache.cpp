#include "dnscache.h"

#include "cidr.h"

#include <QDateTime>
#include <QHostInfo>
#include <QPointer>

namespace qpr {

DnsCache *DnsCache::instance()
{
    static DnsCache *cache = new DnsCache;
    return cache;
}

DnsCache::DnsCache(QObject *parent)
    : QObject(parent)
{
}

void DnsCache::resolve(const QString &host, QObject *context, std::function<void(QHostAddress, QString)> done)
{
    const QString key = host.trimmed().toLower();
    if (isIpAddress(key)) {
        done(QHostAddress(key), {});
        return;
    }
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    const auto it = cache_.constFind(key);
    if (it != cache_.constEnd() && it->expires > now) {
        done(it->address, {});
        return;
    }
    QPointer<QObject> guard(context);
    QHostInfo::lookupHost(key, context, [this, key, guard, done](const QHostInfo &info) {
        if (!guard)
            return;
        if (info.error() != QHostInfo::NoError || info.addresses().isEmpty()) {
            done({}, info.errorString().isEmpty()
                          ? QString::fromUtf8("DNS не резолвится: %1").arg(key)
                          : info.errorString());
            return;
        }
        QHostAddress chosen;
        for (const QHostAddress &address : info.addresses()) {
            if (address.protocol() == QAbstractSocket::IPv4Protocol) {
                chosen = address;
                break;
            }
        }
        if (chosen.isNull())
            chosen = info.addresses().first();
        cache_.insert(key, Entry{chosen, QDateTime::currentMSecsSinceEpoch() + 120000});
        done(chosen, {});
    });
}

} // namespace qpr
