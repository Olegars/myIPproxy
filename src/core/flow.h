#pragma once

#include "pipe.h"
#include "types.h"

namespace qpr {

class Flow : public QObject {
    Q_OBJECT
public:
    explicit Flow(FlowSnapshot snapshot, QObject *parent = nullptr);

    QString id() const { return snap_.id; }
    FlowSnapshot snapshot() const { return snap_; }
    void setStatus(const QString &status, const QString &error = {});
    void setRoute(const QString &via, const QString &rule, const QString &destination);
    void attach(Pipe *client, Pipe *upstream);
    void stop();
    void addSent(quint64 bytes);
    void addReceived(quint64 bytes);

signals:
    void changed();
    void finished();

private:
    void closed(const QString &error);
    void haltSockets();

    FlowSnapshot snap_;
    Pipe *client_ = nullptr;
    Pipe *upstream_ = nullptr;
    bool closing_ = false;
};

} // namespace qpr
