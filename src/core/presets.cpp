#include "presets.h"

#include "netranges.h"

#include <QHash>

namespace qpr {
namespace {

QString domains(std::initializer_list<const char *> names)
{
    QStringList out;
    for (const char *name : names) {
        const QString host = QString::fromUtf8(name);
        out.append(host);
        out.append(QLatin1String("*.") + host);
    }
    return out.join(QLatin1Char(','));
}

QString plain(QString text)
{
    text.replace(QChar(0x2014), QLatin1Char('-'));
    text.replace(QChar(0x2013), QLatin1Char('-'));
    return text.trimmed();
}

const SocialNet *netByComment(const QString &comment, bool *netsOnly)
{
    const QString text = plain(comment);
    for (const SocialNet &net : socialNets()) {
        if (text == net.title) {
            *netsOnly = false;
            return &net;
        }
        if (text == net.title + QStringLiteral(" - сети")) {
            *netsOnly = true;
            return &net;
        }
    }
    return nullptr;
}

bool sameRule(const Rule &left, const Rule &right)
{
    return left.id == right.id && left.enabled == right.enabled && left.process == right.process
        && left.target == right.target && left.ports == right.ports && left.action == right.action
        && left.proxyId == right.proxyId && left.chainId == right.chainId && left.comment == right.comment
        && left.builtin == right.builtin;
}

} // namespace

const QList<SocialNet> &socialNets()
{
    static const QString telegramNets = QStringLiteral(
        "91.108.4.0/22,91.108.8.0/22,91.108.12.0/22,91.108.16.0/22,91.108.20.0/22,"
        "91.108.56.0/22,91.105.192.0/23,149.154.160.0/20,185.76.151.0/24");
    static const QList<SocialNet> nets = {
        {QStringLiteral("youtube"), QString::fromUtf8("YouTube"),
         domains({"youtube.com", "youtu.be", "youtube-nocookie.com", "youtubekids.com", "googlevideo.com",
                  "ytimg.com", "ggpht.com", "gstatic.com", "googleusercontent.com", "googleapis.com",
                  "youtubei.googleapis.com", "youtube.googleapis.com"}),
         googleIpv4Nets()},
        {QStringLiteral("instagram"), QString::fromUtf8("Instagram"),
         domains({"instagram.com", "cdninstagram.com", "instagram.net", "ig.me", "igsonar.com"}),
         metaIpv4Nets()},
        {QStringLiteral("facebook"), QString::fromUtf8("Facebook"),
         domains({"facebook.com", "fb.com", "fbcdn.net", "fbsbx.com", "messenger.com", "facebook.net"}),
         QString()},
        {QStringLiteral("tiktok"), QString::fromUtf8("TikTok"),
         domains({"tiktok.com", "tiktokcdn.com", "tiktokv.com", "tiktokcdn-us.com", "musical.ly", "byteoversea.com",
                  "ibyteimg.com"}),
         QString()},
        {QStringLiteral("discord"), QString::fromUtf8("Discord"),
         domains({"discord.com", "discordapp.com", "discord.gg", "discordapp.net", "discord.media", "discordcdn.com"}),
         QString()},
        {QStringLiteral("whatsapp"), QString::fromUtf8("WhatsApp"),
         domains({"whatsapp.com", "whatsapp.net", "wa.me"}), QString()},
        {QStringLiteral("x"), QString::fromUtf8("X (Twitter)"),
         domains({"x.com", "twitter.com", "twimg.com", "t.co", "pscp.tv"}), QString()},
        {QStringLiteral("telegram"), QString::fromUtf8("Telegram"),
         domains({"telegram.org", "t.me", "telegram.me", "telesco.pe", "cdn-telegram.org", "web.telegram.org"}),
         telegramNets},
        {QStringLiteral("crypto"), QString::fromUtf8("Крипта"),
         domains({"binance.com", "bnbstatic.com", "bybit.com", "okx.com", "htx.com", "huobi.com",
                  "kucoin.com", "gate.io", "gate.com", "bitget.com", "mexc.com", "bingx.com",
                  "whitebit.com", "bitfinex.com", "kraken.com", "coinbase.com", "poloniex.com",
                  "phemex.com", "bitmart.com", "lbank.com", "coinex.com", "bitstamp.net",
                  "tradingview.com", "coingecko.com", "coinmarketcap.com", "metamask.io",
                  "trustwallet.com", "infura.io", "alchemy.com", "ankr.com", "publicnode.com",
                  "drpc.org", "1rpc.io", "nodereal.io", "getblock.io", "quicknode.com",
                  "tonapi.io", "toncenter.com", "tonkeeper.com", "ton.org", "phantom.app",
                  "exodus.com", "exodus.io", "tronlink.org", "trongrid.io", "tronscan.org",
                  "safepal.com", "safepal.io", "walletconnect.com", "walletconnect.org", "reown.com",
                  "myetherwallet.com", "atomicwallet.io", "rabby.io"}),
         QString()},
    };
    return nets;
}

const SocialNet *socialNet(const QString &id)
{
    for (const SocialNet &net : socialNets()) {
        if (net.id == id)
            return &net;
    }
    return nullptr;
}

QString socialTarget(const SocialNet &net)
{
    if (net.nets.isEmpty())
        return net.domains;
    if (net.domains.isEmpty())
        return net.nets;
    return net.domains + QLatin1Char(',') + net.nets;
}

bool ensureSocialRules(AppConfig &config)
{
    const QList<Rule> before = config.rules;
    QHash<QString, Rule> found;
    QList<QString> netsOnly;
    QList<Rule> custom;
    for (const Rule &rule : config.rules) {
        bool onlyNets = false;
        const SocialNet *net = rule.builtin.isEmpty() ? nullptr : socialNet(rule.builtin);
        if (!net)
            net = netByComment(rule.comment, &onlyNets);
        if (!net) {
            custom.append(rule);
            continue;
        }
        if (!found.contains(net->id)) {
            found.insert(net->id, rule);
            if (onlyNets)
                netsOnly.append(net->id);
            continue;
        }
        if (onlyNets)
            continue;
        if (netsOnly.contains(net->id)) {
            found[net->id] = rule;
            netsOnly.removeAll(net->id);
        }
    }

    QList<Rule> social;
    for (const SocialNet &net : socialNets()) {
        Rule rule = found.value(net.id);
        if (rule.id.isEmpty()) {
            rule.id = newId();
            rule.enabled = false;
            rule.action = RuleAction::Proxy;
        }
        rule.builtin = net.id;
        rule.comment = net.title;
        rule.process = QStringLiteral("*");
        rule.target = socialTarget(net);
        rule.ports.clear();
        if (rule.action != RuleAction::Proxy && rule.action != RuleAction::Chain)
            rule.action = RuleAction::Proxy;
        if (rule.proxyId.isEmpty())
            rule.enabled = false;
        social.append(rule);
    }
    config.rules = social + custom;
    if (before.size() != config.rules.size())
        return true;
    for (int i = 0; i < before.size(); ++i) {
        if (!sameRule(before.at(i), config.rules.at(i)))
            return true;
    }
    return false;
}

} // namespace qpr
