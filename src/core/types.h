#pragma once

#include <QDateTime>
#include <QHostAddress>
#include <QList>
#include <QString>
#include <QStringList>
#include <QUuid>

namespace qpr {

enum class ProxyType { Socks4, Socks4a, Socks5, Http, Https, Shield };
enum class RuleAction { Direct, Block, Proxy, Chain };
enum class LogLevel { Info, Warning, Error };

struct Proxy {
    QString id;
    QString name;
    ProxyType type = ProxyType::Socks5;
    QString host;
    quint16 port = 1080;
    QString user;
    QString password;
    bool shield = false;
    QString coverHost = QStringLiteral("ya.ru");
    QString shieldPsk;
    bool tlsInsecure = false;
};

struct Chain {
    QString id;
    QString name;
    QStringList proxyIds;
};

struct Rule {
    QString id;
    bool enabled = true;
    QString process;
    QString target;
    QString ports;
    RuleAction action = RuleAction::Direct;
    QString proxyId;
    QString chainId;
    QString comment;
    QString builtin;
};

struct AppConfig {
    QString listenHost = QStringLiteral("127.0.0.1");
    quint16 socksPort = 10800;
    quint16 httpPort = 10801;
    bool httpEnabled = true;
    bool socksEnabled = true;
    bool autostart = false;
    bool systemProxy = false;
    int logLimit = 5000;
    bool remoteDns = true;
    bool routingEnabled = false;
    bool shieldListen = false;
    QString shieldListenHost = QStringLiteral("127.0.0.1");
    quint16 shieldPort = 9443;
    QString shieldPsk;
    QString hotkey = QStringLiteral("Ctrl+Shift+P");
    QList<Proxy> proxies;
    QList<Chain> chains;
    QList<Rule> rules;
};

struct Endpoint {
    QString process;
    quint32 pid = 0;
    QString host;
    QHostAddress ip;
    quint16 port = 0;
    bool udp = false;
};

struct Decision {
    RuleAction action = RuleAction::Direct;
    QList<Proxy> hops;
    QString ruleId;
    QString summary;
    bool needIp = false;
};

struct FlowSnapshot {
    QString id;
    QDateTime started;
    QString process;
    quint32 pid = 0;
    QString source;
    QString destination;
    QString status;
    QString via;
    QString rule;
    quint64 sent = 0;
    quint64 received = 0;
    QString error;
    bool udp = false;
};

inline QString newId()
{
    return QUuid::createUuid().toString(QUuid::WithoutBraces);
}

inline QString proxyTypeKey(ProxyType t)
{
    switch (t) {
    case ProxyType::Socks4: return QStringLiteral("socks4");
    case ProxyType::Socks4a: return QStringLiteral("socks4a");
    case ProxyType::Socks5: return QStringLiteral("socks5");
    case ProxyType::Http: return QStringLiteral("http");
    case ProxyType::Https: return QStringLiteral("https");
    case ProxyType::Shield: return QStringLiteral("shield");
    }
    return QStringLiteral("socks5");
}

inline ProxyType proxyTypeFromKey(const QString &s)
{
    const QString k = s.toLower();
    if (k == QLatin1String("socks4")) return ProxyType::Socks4;
    if (k == QLatin1String("socks4a")) return ProxyType::Socks4a;
    if (k == QLatin1String("http")) return ProxyType::Http;
    if (k == QLatin1String("https")) return ProxyType::Https;
    if (k == QLatin1String("shield")) return ProxyType::Shield;
    return ProxyType::Socks5;
}

inline QString proxyTypeLabel(ProxyType t)
{
    switch (t) {
    case ProxyType::Socks4: return QStringLiteral("SOCKS4");
    case ProxyType::Socks4a: return QStringLiteral("SOCKS4a");
    case ProxyType::Socks5: return QStringLiteral("SOCKS5");
    case ProxyType::Http: return QStringLiteral("HTTP");
    case ProxyType::Https: return QStringLiteral("HTTPS");
    case ProxyType::Shield: return QString::fromUtf8("Shield (свой выход)");
    }
    return QStringLiteral("SOCKS5");
}

inline QString ruleActionKey(RuleAction a)
{
    switch (a) {
    case RuleAction::Block: return QStringLiteral("block");
    case RuleAction::Proxy: return QStringLiteral("proxy");
    case RuleAction::Chain: return QStringLiteral("chain");
    case RuleAction::Direct: break;
    }
    return QStringLiteral("direct");
}

inline RuleAction ruleActionFromKey(const QString &s)
{
    if (s == QLatin1String("block")) return RuleAction::Block;
    if (s == QLatin1String("proxy")) return RuleAction::Proxy;
    if (s == QLatin1String("chain")) return RuleAction::Chain;
    return RuleAction::Direct;
}

inline QString effectivePsk(const Proxy &p)
{
    if (!p.shieldPsk.isEmpty())
        return p.shieldPsk;
    return p.password;
}

inline bool transportIsShield(const Proxy &p)
{
    return p.type == ProxyType::Shield || p.shield;
}

inline QString coverOrDefault(const Proxy &p)
{
    const QString c = p.coverHost.trimmed();
    return c.isEmpty() ? QStringLiteral("ya.ru") : c;
}

} // namespace qpr
