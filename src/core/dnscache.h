#pragma once

#include <QHash>
#include <QHostAddress>
#include <QObject>
#include <functional>

namespace qpr {

class DnsCache : public QObject {
    Q_OBJECT
public:
    static DnsCache *instance();
    void resolve(const QString &host, QObject *context, std::function<void(QHostAddress, QString)> done);

private:
    explicit DnsCache(QObject *parent = nullptr);
    struct Entry {
        QHostAddress address;
        qint64 expires = 0;
    };
    QHash<QString, Entry> cache_;
};

} // namespace qpr
