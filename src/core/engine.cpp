#include "engine.h"

#include "cidr.h"
#include "divertor.h"
#include "dnscache.h"
#include "inbound.h"
#include "logger.h"
#include "presets.h"
#include "proxytest.h"
#include "ruleengine.h"
#include "shieldserver.h"

#include <QDateTime>
#include <QHostAddress>
#include <QTimer>
#include <algorithm>

namespace qpr {

Engine::Engine(QObject *parent)
    : QObject(parent)
    , inbound_(new InboundServer(this))
    , divertor_(new PacketDivert(inbound_, this))
    , shield_(new ShieldServer(this))
    , configPath_(ConfigStore::defaultPath())
{
    trimTimer_ = new QTimer(this);
    trimTimer_->setInterval(2000);
    connect(trimTimer_, &QTimer::timeout, this, &Engine::trim);
}

void Engine::load()
{
    QString error;
    config_ = ConfigStore::load(configPath_, &error);
    if (error.isEmpty() && ensureSocialRules(config_)) {
        QString saveError;
        if (!ConfigStore::save(configPath_, config_, &saveError))
            Logger::instance()->warn(QString::fromUtf8("Не сохранил встроенные правила: %1").arg(saveError));
    }
    loaded_ = true;
    Logger::instance()->setLimit(config_.logLimit);
    if (!error.isEmpty())
        Logger::instance()->warn(QString::fromUtf8("Настройки: %1").arg(error));
    else
        Logger::instance()->info(QString::fromUtf8("Настройки: %1").arg(configPath_));
}

void Engine::setConfig(AppConfig config)
{
    const bool rebindNeeded = listening_ && endpointsDiffer(config);
    config_ = std::move(config);
    Logger::instance()->setLimit(config_.logLimit);
    QString error;
    if (!ConfigStore::save(configPath_, config_, &error))
        Logger::instance()->error(QString::fromUtf8("Не сохранил настройки: %1").arg(error));
    shield_->setPsk(config_.shieldPsk);
    if (delegated_) {
        applySideEffects();
        emit routingChanged(config_.routingEnabled);
        return;
    }
    if (rebindNeeded)
        rebind();
    else if (listening_)
        applySideEffects();
    emit routingChanged(config_.routingEnabled);
}

void Engine::setRoutingEnabled(bool enabled)
{
    if (config_.routingEnabled == enabled)
        return;
    config_.routingEnabled = enabled;
    QString error;
    if (!ConfigStore::save(configPath_, config_, &error))
        Logger::instance()->error(QString::fromUtf8("Не сохранил настройки: %1").arg(error));
    applySideEffects();
    Logger::instance()->info(enabled
                                 ? QString::fromUtf8("Маршрутизация включена")
                                 : QString::fromUtf8("Маршрутизация выключена, новые соединения идут напрямую"));
    emit routingChanged(enabled);
}

void Engine::reload()
{
    load();
    Logger::instance()->setLimit(config_.logLimit);
    rebind();
}

bool Engine::start()
{
    if (!loaded_)
        load();
    rebind();
    if (!delegated_)
        trimTimer_->start();
    return listening();
}

void Engine::releasePorts()
{
    divertor_->stop();
    inbound_->closeListeners();
    shield_->closeListener();
    listening_ = false;
}

void Engine::stop()
{
    if (delegated_) {
        trimTimer_->stop();
        return;
    }
    divertor_->stop();
    inbound_->closeListeners();
    shield_->closeListener();
    systemProxy_.restore();
    const auto flows = flows_.values();
    for (Flow *flow : flows)
        flow->stop();
    listening_ = false;
    trimTimer_->stop();
    emit listeningChanged(false);
}

quint16 Engine::socksPort() const { return delegated_ ? remoteSocks_ : inbound_->socksPort(); }
quint16 Engine::httpPort() const { return delegated_ ? remoteHttp_ : inbound_->httpPort(); }
quint16 Engine::shieldPort() const { return delegated_ ? remoteShield_ : shield_->port(); }
bool Engine::divertActive() const { return delegated_ ? remoteDivert_ : divertor_->active(); }
quint16 Engine::divertPort() const { return delegated_ ? remoteDivertPort_ : divertor_->port(); }

void Engine::applyRemoteStatus(bool listening, quint16 socks, quint16 http, quint16 shield, bool divert, quint16 divertPort)
{
    remoteListening_ = listening;
    remoteSocks_ = socks;
    remoteHttp_ = http;
    remoteShield_ = shield;
    remoteDivert_ = divert;
    remoteDivertPort_ = divertPort;
    emit listeningChanged(listening);
    if (delegated_)
        applySideEffects();
}

void Engine::applyRemoteFlows(QList<FlowSnapshot> rows)
{
    remoteFlows_ = std::move(rows);
    emit flowsChanged();
}

QList<FlowSnapshot> Engine::snapshots() const
{
    if (delegated_)
        return remoteFlows_;
    QList<FlowSnapshot> rows;
    rows.reserve(flows_.size());
    for (Flow *flow : flows_)
        rows.append(flow->snapshot());
    std::sort(rows.begin(), rows.end(), [](const FlowSnapshot &a, const FlowSnapshot &b) {
        return a.started > b.started;
    });
    return rows;
}

void Engine::closeFlow(const QString &id)
{
    if (Flow *flow = flows_.value(id))
        flow->stop();
}

void Engine::closePid(quint32 pid)
{
    const auto flows = flows_.values();
    for (Flow *flow : flows) {
        if (flow->snapshot().pid == pid)
            flow->stop();
    }
}

void Engine::clearClosed()
{
    const auto ids = flows_.keys();
    for (const QString &id : ids) {
        Flow *flow = flows_.value(id);
        const QString status = flow->snapshot().status;
        if (status == QString::fromUtf8("Закрыто") || status == QString::fromUtf8("Ошибка")
            || status == QString::fromUtf8("Заблокировано")) {
            flows_.remove(id);
            flow->deleteLater();
        }
    }
    emit flowsChanged();
}

void Engine::testProxy(const Proxy &proxy, std::function<void(const QString &, bool)> done)
{
    runProxyTest(proxy, this, std::move(done));
}

void Engine::testChain(const Chain &chain, std::function<void(const QString &, bool)> done)
{
    QList<Proxy> hops;
    for (const QString &id : chain.proxyIds) {
        for (const Proxy &proxy : config_.proxies) {
            if (proxy.id == id) {
                hops.append(proxy);
                break;
            }
        }
    }
    runChainTest(hops, config_.remoteDns, this, std::move(done));
}

void Engine::prepare(const Endpoint &endpoint, std::function<void(Decision, Endpoint)> done)
{
    Endpoint current = endpoint;
    Decision decision = matchRules(config_, current);
    if (!decision.needIp) {
        done(decision, current);
        return;
    }
    if (isIpAddress(current.host)) {
        current.ip = QHostAddress(current.host);
        done(matchRules(config_, current), current);
        return;
    }
    DnsCache::instance()->resolve(current.host, this, [this, current, done](QHostAddress address, QString error) mutable {
        if (!error.isEmpty()) {
            Logger::instance()->warn(QString::fromUtf8("Локальный DNS для правила %1: %2").arg(current.host, error));
            done(matchRules(config_, current, true), current);
            return;
        }
        current.ip = address;
        Logger::instance()->info(QString::fromUtf8("Локальный DNS для правила: %1 → %2")
                                     .arg(current.host, address.toString()));
        done(matchRules(config_, current), current);
    });
}

Flow *Engine::makeFlow(FlowSnapshot snapshot)
{
    if (flows_.size() >= 300)
        trim();
    if (flows_.size() >= 300)
        return nullptr;
    auto *flow = new Flow(std::move(snapshot), this);
    flows_.insert(flow->id(), flow);
    connect(flow, &Flow::changed, this, &Engine::flowsChanged);
    connect(flow, &Flow::finished, this, [this] { trim(); emit flowsChanged(); });
    trim();
    emit flowsChanged();
    return flow;
}

void Engine::rebind()
{
    if (delegated_) {
        applySideEffects();
        emit listeningChanged(remoteListening_);
        emit routingChanged(config_.routingEnabled);
        return;
    }
    inbound_->closeListeners();
    shield_->closeListener();
    InboundServer::Hooks hooks;
    hooks.prepare = [this](Endpoint endpoint, std::function<void(Decision, Endpoint)> done) {
        prepare(endpoint, std::move(done));
    };
    hooks.makeFlow = [this](FlowSnapshot snapshot) { return makeFlow(std::move(snapshot)); };
    hooks.remoteDns = [this] { return config_.remoteDns; };
    hooks.rejectSelf = [this] { return config_.routingEnabled && config_.systemProxy; };
    hooks.overloaded = [this] { return flows_.size() >= 300; };
    inbound_->setHooks(hooks);
    shield_->setPsk(config_.shieldPsk);

    QHostAddress listen(config_.listenHost);
    if (listen.isNull())
        listen = QHostAddress::LocalHost;
    bool ok = true;
    if (config_.socksEnabled)
        ok = inbound_->listenSocks(listen, config_.socksPort) && ok;
    if (config_.httpEnabled)
        ok = inbound_->listenHttp(listen, config_.httpPort) && ok;
    if (config_.shieldListen) {
        QHostAddress shieldAddr(config_.shieldListenHost);
        if (shieldAddr.isNull())
            shieldAddr = QHostAddress::LocalHost;
        ok = shield_->listen(shieldAddr, config_.shieldPort) && ok;
    }
    listening_ = ok || inbound_->socksPort() || inbound_->httpPort() || shield_->port();
    applySideEffects();
    emit listeningChanged(listening_);
    emit routingChanged(config_.routingEnabled);
}

void Engine::applySideEffects()
{
    if (serviceMode_) {
        applyDivert();
        return;
    }
    setAutostart(config_.autostart);
    const bool wantProxy = listening() && config_.routingEnabled && config_.systemProxy && config_.httpEnabled;
    if (wantProxy) {
        const bool was = systemProxy_.active();
        const quint16 port = httpPort() ? httpPort() : config_.httpPort;
        if (systemProxy_.enable(config_.listenHost, port)) {
            if (!was)
                Logger::instance()->info(QString::fromUtf8("Системный прокси Windows: %1:%2")
                                             .arg(config_.listenHost)
                                             .arg(port));
        } else {
            Logger::instance()->error(QString::fromUtf8("Не удалось включить системный прокси Windows"));
        }
    } else if (systemProxy_.active()) {
        systemProxy_.restore();
        Logger::instance()->info(QString::fromUtf8("Системный прокси Windows выключен"));
    }
    applyDivert();
}

void Engine::applyDivert()
{
    if (delegated_)
        return;
    divertor_->setConfig(config_);
    if (listening_ && config_.routingEnabled) {
        if (!divertor_->active())
            divertor_->start();
    } else {
        divertor_->stop();
    }
}

bool Engine::endpointsDiffer(const AppConfig &other) const
{
    return other.listenHost != config_.listenHost
        || other.socksPort != config_.socksPort
        || other.httpPort != config_.httpPort
        || other.socksEnabled != config_.socksEnabled
        || other.httpEnabled != config_.httpEnabled
        || other.shieldListen != config_.shieldListen
        || other.shieldListenHost != config_.shieldListenHost
        || other.shieldPort != config_.shieldPort;
}

void Engine::trim()
{
    if (trimming_)
        return;
    trimming_ = true;
    const QString connecting = QString::fromUtf8("Подключение");
    const QString established = QString::fromUtf8("Установлено");
    const QDateTime now = QDateTime::currentDateTime();
    const auto oldestFirst = [](Flow *a, Flow *b) {
        return a->snapshot().started < b->snapshot().started;
    };

    QList<Flow *> aged;
    for (Flow *flow : flows_) {
        const FlowSnapshot snap = flow->snapshot();
        if (snap.status == connecting && snap.started.msecsTo(now) > 20000)
            aged.append(flow);
    }
    for (Flow *flow : aged)
        flow->stop();

    if (flows_.size() > 300) {
        QList<Flow *> pending;
        for (Flow *flow : flows_) {
            if (flow->snapshot().status == connecting)
                pending.append(flow);
        }
        std::sort(pending.begin(), pending.end(), oldestFirst);
        while (flows_.size() > 250 && !pending.isEmpty())
            pending.takeFirst()->stop();
    }

    if (flows_.size() > 200) {
        QList<Flow *> closed;
        for (Flow *flow : flows_) {
            const QString status = flow->snapshot().status;
            if (status != connecting && status != established)
                closed.append(flow);
        }
        std::sort(closed.begin(), closed.end(), oldestFirst);
        while (flows_.size() > 200 && !closed.isEmpty()) {
            Flow *flow = closed.takeFirst();
            flows_.remove(flow->id());
            flow->deleteLater();
        }
    }
    trimming_ = false;
}

} // namespace qpr
