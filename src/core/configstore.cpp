#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef _WIN32_WINNT
#    define _WIN32_WINNT 0x0601
#  endif
#  include <windows.h>
#  include <aclapi.h>
#  include <sddl.h>
#endif

#include "configstore.h"

#include "secretstore.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSaveFile>
#include <QStandardPaths>

namespace qpr {
namespace {

QJsonObject proxyToJson(const Proxy &proxy, QString *error)
{
    QJsonObject obj;
    obj.insert(QStringLiteral("id"), proxy.id);
    obj.insert(QStringLiteral("name"), proxy.name);
    obj.insert(QStringLiteral("type"), proxyTypeKey(proxy.type));
    obj.insert(QStringLiteral("host"), proxy.host);
    obj.insert(QStringLiteral("port"), proxy.port);
    obj.insert(QStringLiteral("user"), proxy.user);
    const QString password = SecretStore::seal(proxy.password);
    const QString psk = SecretStore::seal(proxy.shieldPsk);
    if ((!proxy.password.isEmpty() && password.isEmpty()) || (!proxy.shieldPsk.isEmpty() && psk.isEmpty())) {
        if (error)
            *error = QString::fromUtf8("не удалось зашифровать пароль");
        return {};
    }
    obj.insert(QStringLiteral("password"), password);
    obj.insert(QStringLiteral("shield"), proxy.shield);
    obj.insert(QStringLiteral("coverHost"), proxy.coverHost);
    obj.insert(QStringLiteral("shieldPsk"), psk);
    obj.insert(QStringLiteral("tlsInsecure"), proxy.tlsInsecure);
    return obj;
}

Proxy proxyFromJson(const QJsonObject &obj)
{
    Proxy proxy;
    proxy.id = obj.value(QStringLiteral("id")).toString();
    proxy.name = obj.value(QStringLiteral("name")).toString();
    proxy.type = proxyTypeFromKey(obj.value(QStringLiteral("type")).toString());
    proxy.host = obj.value(QStringLiteral("host")).toString();
    proxy.port = static_cast<quint16>(obj.value(QStringLiteral("port")).toInt());
    proxy.user = obj.value(QStringLiteral("user")).toString();
    proxy.password = SecretStore::open(obj.value(QStringLiteral("password")).toString());
    proxy.shield = obj.value(QStringLiteral("shield")).toBool();
    proxy.coverHost = obj.value(QStringLiteral("coverHost")).toString(QStringLiteral("ya.ru"));
    proxy.shieldPsk = SecretStore::open(obj.value(QStringLiteral("shieldPsk")).toString());
    proxy.tlsInsecure = obj.value(QStringLiteral("tlsInsecure")).toBool();
    if (proxy.id.isEmpty())
        proxy.id = newId();
    return proxy;
}

QJsonObject ruleToJson(const Rule &rule)
{
    QJsonObject obj;
    obj.insert(QStringLiteral("id"), rule.id);
    obj.insert(QStringLiteral("enabled"), rule.enabled);
    obj.insert(QStringLiteral("process"), rule.process);
    obj.insert(QStringLiteral("target"), rule.target);
    obj.insert(QStringLiteral("ports"), rule.ports);
    obj.insert(QStringLiteral("action"), ruleActionKey(rule.action));
    obj.insert(QStringLiteral("proxyId"), rule.proxyId);
    obj.insert(QStringLiteral("chainId"), rule.chainId);
    obj.insert(QStringLiteral("comment"), rule.comment);
    obj.insert(QStringLiteral("builtin"), rule.builtin);
    return obj;
}

Rule ruleFromJson(const QJsonObject &obj)
{
    Rule rule;
    rule.id = obj.value(QStringLiteral("id")).toString();
    rule.enabled = obj.value(QStringLiteral("enabled")).toBool(true);
    rule.process = obj.value(QStringLiteral("process")).toString();
    rule.target = obj.value(QStringLiteral("target")).toString();
    rule.ports = obj.value(QStringLiteral("ports")).toString();
    rule.action = ruleActionFromKey(obj.value(QStringLiteral("action")).toString());
    rule.proxyId = obj.value(QStringLiteral("proxyId")).toString();
    rule.chainId = obj.value(QStringLiteral("chainId")).toString();
    rule.comment = obj.value(QStringLiteral("comment")).toString();
    rule.builtin = obj.value(QStringLiteral("builtin")).toString();
    if (rule.id.isEmpty())
        rule.id = newId();
    return rule;
}

} // namespace

namespace {

void shareConfigDir()
{
#ifdef _WIN32
    const wchar_t *dir = L"C:\\ProgramData\\stopRKN";
    CreateDirectoryW(dir, nullptr);
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)(A;OICI;GA;;;IU)",
            SDDL_REVISION_1, &sd, nullptr)) {
        return;
    }
    BOOL present = FALSE;
    BOOL defaulted = FALSE;
    PACL dacl = nullptr;
    if (GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted)) {
        SetNamedSecurityInfoW(const_cast<wchar_t *>(dir), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                              nullptr, nullptr, dacl, nullptr);
    }
    LocalFree(sd);
#endif
}

} // namespace

QString ConfigStore::defaultPath()
{
#ifdef Q_OS_WIN
    shareConfigDir();
    const QString path = QStringLiteral("C:/ProgramData/stopRKN/config.json");
    if (!QFile::exists(path)) {
        const QString previous = QStringLiteral("C:/ProgramData/myIPproxy/config.json");
        const QString legacy = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation)
            + QStringLiteral("/config.json");
        if (QFile::exists(previous))
            QFile::copy(previous, path);
        else if (QFile::exists(legacy))
            QFile::copy(legacy, path);
    }
    return path;
#else
    const QString dir = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
    return dir + QStringLiteral("/config.json");
#endif
}

bool ConfigStore::needsMachinePromotion(const QString &path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly))
        return false;
    return QString::fromUtf8(file.readAll()).contains(QStringLiteral("\"dpapi:"));
}

AppConfig ConfigStore::load(const QString &path, QString *error)
{
    AppConfig config;
    QFile file(path);
    if (!file.exists())
        return config;
    if (!file.open(QIODevice::ReadOnly)) {
        if (error)
            *error = file.errorString();
        return config;
    }
    const QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
    if (!doc.isObject()) {
        if (error)
            *error = QString::fromUtf8("повреждён файл настроек");
        return config;
    }
    const QJsonObject root = doc.object();
    config.listenHost = root.value(QStringLiteral("listenHost")).toString(config.listenHost);
    config.socksPort = static_cast<quint16>(root.value(QStringLiteral("socksPort")).toInt(config.socksPort));
    config.httpPort = static_cast<quint16>(root.value(QStringLiteral("httpPort")).toInt(config.httpPort));
    config.httpEnabled = root.value(QStringLiteral("httpEnabled")).toBool(config.httpEnabled);
    config.socksEnabled = root.value(QStringLiteral("socksEnabled")).toBool(config.socksEnabled);
    config.autostart = root.value(QStringLiteral("autostart")).toBool();
    config.systemProxy = root.value(QStringLiteral("systemProxy")).toBool();
    config.logLimit = root.value(QStringLiteral("logLimit")).toInt(config.logLimit);
    config.remoteDns = root.value(QStringLiteral("remoteDns")).toBool(true);
    config.routingEnabled = root.value(QStringLiteral("routingEnabled")).toBool();
    config.shieldListen = root.value(QStringLiteral("shieldListen")).toBool();
    config.shieldListenHost = root.value(QStringLiteral("shieldListenHost")).toString(config.shieldListenHost);
    config.shieldPort = static_cast<quint16>(root.value(QStringLiteral("shieldPort")).toInt(config.shieldPort));
    config.shieldPsk = SecretStore::open(root.value(QStringLiteral("shieldPsk")).toString());
    config.hotkey = root.value(QStringLiteral("hotkey")).toString(config.hotkey);
    for (const QJsonValue &value : root.value(QStringLiteral("proxies")).toArray())
        config.proxies.append(proxyFromJson(value.toObject()));
    for (const QJsonValue &value : root.value(QStringLiteral("chains")).toArray()) {
        const QJsonObject obj = value.toObject();
        Chain chain;
        chain.id = obj.value(QStringLiteral("id")).toString();
        chain.name = obj.value(QStringLiteral("name")).toString();
        for (const QJsonValue &id : obj.value(QStringLiteral("proxyIds")).toArray())
            chain.proxyIds.append(id.toString());
        if (chain.id.isEmpty())
            chain.id = newId();
        config.chains.append(chain);
    }
    for (const QJsonValue &value : root.value(QStringLiteral("rules")).toArray())
        config.rules.append(ruleFromJson(value.toObject()));
    return config;
}

bool ConfigStore::save(const QString &path, const AppConfig &config, QString *error)
{
    QJsonObject root;
    root.insert(QStringLiteral("version"), 1);
    root.insert(QStringLiteral("listenHost"), config.listenHost);
    root.insert(QStringLiteral("socksPort"), config.socksPort);
    root.insert(QStringLiteral("httpPort"), config.httpPort);
    root.insert(QStringLiteral("httpEnabled"), config.httpEnabled);
    root.insert(QStringLiteral("socksEnabled"), config.socksEnabled);
    root.insert(QStringLiteral("autostart"), config.autostart);
    root.insert(QStringLiteral("systemProxy"), config.systemProxy);
    root.insert(QStringLiteral("logLimit"), config.logLimit);
    root.insert(QStringLiteral("remoteDns"), config.remoteDns);
    root.insert(QStringLiteral("routingEnabled"), config.routingEnabled);
    root.insert(QStringLiteral("shieldListen"), config.shieldListen);
    root.insert(QStringLiteral("shieldListenHost"), config.shieldListenHost);
    root.insert(QStringLiteral("shieldPort"), config.shieldPort);
    root.insert(QStringLiteral("shieldPsk"), SecretStore::seal(config.shieldPsk));
    root.insert(QStringLiteral("hotkey"), config.hotkey);
    QJsonArray proxies;
    for (const Proxy &proxy : config.proxies) {
        const QJsonObject obj = proxyToJson(proxy, error);
        if (obj.isEmpty() && !proxy.id.isEmpty())
            return false;
        proxies.append(obj);
    }
    root.insert(QStringLiteral("proxies"), proxies);
    QJsonArray chains;
    for (const Chain &chain : config.chains) {
        QJsonObject obj;
        obj.insert(QStringLiteral("id"), chain.id);
        obj.insert(QStringLiteral("name"), chain.name);
        QJsonArray ids;
        for (const QString &id : chain.proxyIds)
            ids.append(id);
        obj.insert(QStringLiteral("proxyIds"), ids);
        chains.append(obj);
    }
    root.insert(QStringLiteral("chains"), chains);
    QJsonArray rules;
    for (const Rule &rule : config.rules)
        rules.append(ruleToJson(rule));
    root.insert(QStringLiteral("rules"), rules);

    QDir().mkpath(QFileInfo(path).absolutePath());
    if (QFile::exists(path))
        QFile::copy(path, path + QStringLiteral(".bak"));
    QSaveFile file(path);
    if (!file.open(QIODevice::WriteOnly)) {
        if (error)
            *error = file.errorString();
        return false;
    }
    file.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
    if (!file.commit()) {
        if (error)
            *error = file.errorString();
        return false;
    }
    return true;
}

} // namespace qpr
