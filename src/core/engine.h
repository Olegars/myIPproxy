#pragma once

#include "configstore.h"
#include "flow.h"
#include "platform.h"
#include "types.h"

#include <QHash>
#include <QObject>
#include <functional>

class QTimer;

namespace qpr {

class InboundServer;
class PacketDivert;
class ShieldServer;

class Engine : public QObject {
    Q_OBJECT
public:
    explicit Engine(QObject *parent = nullptr);

    void load();
    const AppConfig &config() const { return config_; }
    void setConfig(AppConfig config);
    void setRoutingEnabled(bool enabled);
    void reload();
    bool start();
    void stop();
    void releasePorts();
    void setServiceMode(bool on) { serviceMode_ = on; }
    void setDelegated(bool on) { delegated_ = on; }
    bool delegated() const { return delegated_; }
    void applyRemoteStatus(bool listening, quint16 socks, quint16 http, quint16 shield, bool divert, quint16 divertPort);
    void applyRemoteFlows(QList<FlowSnapshot> rows);
    bool listening() const { return delegated_ ? remoteListening_ : listening_; }

    quint16 socksPort() const;
    quint16 httpPort() const;
    quint16 shieldPort() const;
    bool divertActive() const;
    quint16 divertPort() const;
    QList<FlowSnapshot> snapshots() const;
    int flowCount() const { return delegated_ ? remoteFlows_.size() : flows_.size(); }
    void closeFlow(const QString &id);
    void closePid(quint32 pid);
    void clearClosed();
    void testProxy(const Proxy &proxy, std::function<void(const QString &, bool)> done);
    void testChain(const Chain &chain, std::function<void(const QString &, bool)> done);

signals:
    void listeningChanged(bool listening);
    void routingChanged(bool enabled);
    void flowsChanged();

private:
    void prepare(const Endpoint &endpoint, std::function<void(Decision, Endpoint)> done);
    Flow *makeFlow(FlowSnapshot snapshot);
    void rebind();
    void applySideEffects();
    void applyDivert();
    bool endpointsDiffer(const AppConfig &other) const;
    void trim();

    AppConfig config_;
    bool loaded_ = false;
    bool listening_ = false;
    bool delegated_ = false;
    bool serviceMode_ = false;
    bool remoteListening_ = false;
    bool remoteDivert_ = false;
    quint16 remoteSocks_ = 0;
    quint16 remoteHttp_ = 0;
    quint16 remoteShield_ = 0;
    quint16 remoteDivertPort_ = 0;
    QList<FlowSnapshot> remoteFlows_;
    bool trimming_ = false;
    QTimer *trimTimer_ = nullptr;
    InboundServer *inbound_ = nullptr;
    PacketDivert *divertor_ = nullptr;
    ShieldServer *shield_ = nullptr;
    QHash<QString, Flow *> flows_;
    SystemProxy systemProxy_;
    QString configPath_;
};

} // namespace qpr
