#pragma once

#include "pipe.h"
#include "types.h"

#include <QTimer>

namespace qpr {

class Dialer : public QObject {
    Q_OBJECT
public:
    Dialer(QList<Proxy> hops, QString host, quint16 port, bool remoteDns, QObject *parent = nullptr);
    void start();

signals:
    void established(qpr::Pipe *pipe);
    void failed(const QString &error);

private:
    void fail(const QString &error);
    void succeed(Pipe *pipe);
    void watch(Pipe *pipe);
    void begin(int index, Pipe *pipe);
    void runInner(Pipe *transport, const Proxy &hop, int index);
    void startInner(Pipe *transport, const Proxy &hop, int index, const QString &host, quint16 port);
    void nextTarget(int index, QString *host, quint16 *port) const;

    QList<Proxy> hops_;
    QString host_;
    quint16 port_ = 0;
    bool remoteDns_ = true;
    bool done_ = false;
    QMetaObject::Connection watch_;
    QTimer timer_;
};

} // namespace qpr
