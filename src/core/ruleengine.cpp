#include "ruleengine.h"

#include "cidr.h"

#include <QRegularExpression>

namespace qpr {
namespace {

enum class TargetEval { Match, Miss, NeedIp };

bool processMatches(const Rule &rule, const Endpoint &endpoint)
{
    const QString spec = rule.process.trimmed();
    if (spec.isEmpty() || spec == QLatin1String("*"))
        return true;
    const QStringList tokens = spec.split(QRegularExpression(QStringLiteral("[,;]")), Qt::SkipEmptyParts);
    for (const QString &raw : tokens) {
        if (wildMatch(raw, endpoint.process))
            return true;
    }
    return false;
}

bool tokenIsCidr(const QString &token)
{
    return token.contains(QLatin1Char('/'));
}

TargetEval evalTarget(const Rule &rule, const Endpoint &endpoint)
{
    const QString spec = rule.target.trimmed();
    if (spec.isEmpty() || spec == QLatin1String("*"))
        return TargetEval::Match;

    bool needIp = false;
    const QStringList tokens = spec.split(QLatin1Char(','), Qt::SkipEmptyParts);
    for (QString raw : tokens) {
        const QString token = raw.trimmed();
        if (token.isEmpty())
            continue;
        if (tokenIsCidr(token)) {
            if (endpoint.ip.isNull()) {
                needIp = true;
                continue;
            }
            if (cidrContains(token, endpoint.ip))
                return TargetEval::Match;
            continue;
        }
        if (isIpAddress(token)) {
            if (endpoint.host.compare(token, Qt::CaseInsensitive) == 0)
                return TargetEval::Match;
            if (!endpoint.ip.isNull() && endpoint.ip == QHostAddress(token))
                return TargetEval::Match;
            if (endpoint.ip.isNull() && !isIpAddress(endpoint.host))
                needIp = true;
            continue;
        }
        if (wildMatch(token, endpoint.host))
            return TargetEval::Match;
    }
    return needIp ? TargetEval::NeedIp : TargetEval::Miss;
}

const Proxy *findProxy(const AppConfig &config, const QString &id)
{
    for (const Proxy &proxy : config.proxies) {
        if (proxy.id == id)
            return &proxy;
    }
    return nullptr;
}

Decision blocked(const QString &summary)
{
    Decision decision;
    decision.action = RuleAction::Block;
    decision.summary = summary;
    return decision;
}

Decision fromRule(const AppConfig &config, const Rule &rule)
{
    Decision decision;
    decision.action = rule.action;
    decision.ruleId = rule.id;
    decision.summary = rule.comment.trimmed();
    if (decision.summary.isEmpty()) {
        switch (rule.action) {
        case RuleAction::Direct:
            decision.summary = QString::fromUtf8("напрямую");
            break;
        case RuleAction::Block:
            decision.summary = QString::fromUtf8("блок");
            break;
        case RuleAction::Proxy:
            decision.summary = QString::fromUtf8("прокси");
            break;
        case RuleAction::Chain:
            decision.summary = QString::fromUtf8("цепочка");
            break;
        }
    }

    if (rule.action == RuleAction::Direct || rule.action == RuleAction::Block)
        return decision;

    if (rule.action == RuleAction::Proxy) {
        const Proxy *proxy = findProxy(config, rule.proxyId);
        if (!proxy)
            return blocked(QString::fromUtf8("правило ссылается на удалённый прокси"));
        decision.hops.append(*proxy);
        return decision;
    }

    const Chain *chain = nullptr;
    for (const Chain &item : config.chains) {
        if (item.id == rule.chainId) {
            chain = &item;
            break;
        }
    }
    if (!chain || chain->proxyIds.isEmpty())
        return blocked(QString::fromUtf8("правило ссылается на пустую цепочку"));
    for (const QString &id : chain->proxyIds) {
        const Proxy *proxy = findProxy(config, id);
        if (!proxy)
            return blocked(QString::fromUtf8("в цепочке не хватает прокси"));
        decision.hops.append(*proxy);
    }
    return decision;
}

} // namespace

bool wildMatch(const QString &pattern, const QString &text)
{
    const QString spec = pattern.trimmed();
    if (spec.isEmpty() || spec == QLatin1String("*"))
        return true;
    const QRegularExpression re(
        QRegularExpression::wildcardToRegularExpression(spec),
        QRegularExpression::CaseInsensitiveOption);
    return re.match(text).hasMatch();
}

Decision matchRules(const AppConfig &config, const Endpoint &endpoint, bool unresolvedCidrMiss)
{
    if (!config.routingEnabled) {
        Decision decision;
        decision.action = RuleAction::Direct;
        decision.summary = QString::fromUtf8("маршрутизация выключена");
        return decision;
    }

    Decision deferred;
    bool haveDeferred = false;
    bool needIp = false;
    for (const Rule &rule : config.rules) {
        if (!rule.enabled)
            continue;
        if (!processMatches(rule, endpoint))
            continue;
        if (!portsMatch(rule.ports, endpoint.port))
            continue;
        const TargetEval eval = evalTarget(rule, endpoint);
        if (eval == TargetEval::NeedIp) {
            if (!unresolvedCidrMiss)
                needIp = true;
            continue;
        }
        if (eval == TargetEval::Miss)
            continue;
        const bool catchAll = rule.builtin.isEmpty() && rule.target.trimmed().isEmpty();
        if (needIp && catchAll) {
            if (!haveDeferred) {
                deferred = fromRule(config, rule);
                haveDeferred = true;
            }
            continue;
        }
        return fromRule(config, rule);
    }
    if (needIp) {
        Decision decision;
        decision.needIp = true;
        return decision;
    }
    if (haveDeferred)
        return deferred;

    Decision decision;
    decision.action = RuleAction::Direct;
    decision.summary = QString::fromUtf8("нет подходящего правила");
    return decision;
}

QString describeVia(const Decision &decision)
{
    if (decision.action == RuleAction::Block)
        return QString::fromUtf8("блок");
    if (decision.action == RuleAction::Direct || decision.hops.isEmpty())
        return QString::fromUtf8("напрямую");
    QStringList names;
    for (const Proxy &proxy : decision.hops) {
        QString name = proxy.name.isEmpty() ? proxy.host : proxy.name;
        if (transportIsShield(proxy))
            name += QString::fromUtf8(" / прикрытие ") + coverOrDefault(proxy);
        names.append(name);
    }
    return names.join(QString::fromUtf8(" → "));
}

} // namespace qpr
