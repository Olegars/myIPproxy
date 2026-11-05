#include "privacy.h"

#include "dialer.h"
#include "logger.h"
#include "pipe.h"
#include "ruleengine.h"
#include "types.h"

#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QPointer>
#include <QSaveFile>
#include <QSettings>
#include <QStringList>
#include <QTimeZone>
#include <QTimer>

#include <cstring>
#include <functional>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef _WIN32_WINNT
#    define _WIN32_WINNT 0x0601
#  endif
#  include <windows.h>
#endif

namespace qpr {
namespace {

const char kZones[] = R"(
Pacific/Honolulu=Hawaiian Standard Time
America/Anchorage=Alaskan Standard Time
America/Los_Angeles=Pacific Standard Time
America/Vancouver=Pacific Standard Time
America/Tijuana=Pacific Standard Time (Mexico)
America/Phoenix=US Mountain Standard Time
America/Denver=Mountain Standard Time
America/Edmonton=Mountain Standard Time
America/Boise=Mountain Standard Time
America/Chicago=Central Standard Time
America/Winnipeg=Central Standard Time
America/Mexico_City=Central Standard Time (Mexico)
America/Guatemala=Central America Standard Time
America/Regina=Canada Central Standard Time
America/Bogota=SA Pacific Standard Time
America/Lima=SA Pacific Standard Time
America/New_York=Eastern Standard Time
America/Toronto=Eastern Standard Time
America/Detroit=Eastern Standard Time
America/Montreal=Eastern Standard Time
America/Indiana/Indianapolis=US Eastern Standard Time
America/Indianapolis=US Eastern Standard Time
America/Cancun=Eastern Standard Time (Mexico)
America/Halifax=Atlantic Standard Time
America/Caracas=Venezuela Standard Time
America/La_Paz=SA Western Standard Time
America/Santiago=Pacific SA Standard Time
America/St_Johns=Newfoundland Standard Time
America/Sao_Paulo=E. South America Standard Time
America/Cayenne=SA Eastern Standard Time
America/Argentina/Buenos_Aires=Argentina Standard Time
America/Buenos_Aires=Argentina Standard Time
America/Godthab=Greenland Standard Time
America/Nuuk=Greenland Standard Time
America/Montevideo=Montevideo Standard Time
Atlantic/Azores=Azores Standard Time
Atlantic/Cape_Verde=Cape Verde Standard Time
Etc/UTC=UTC
UTC=UTC
Europe/London=GMT Standard Time
Europe/Dublin=GMT Standard Time
Atlantic/Reykjavik=Greenwich Standard Time
Africa/Casablanca=Morocco Standard Time
Europe/Berlin=W. Europe Standard Time
Europe/Amsterdam=W. Europe Standard Time
Europe/Rome=W. Europe Standard Time
Europe/Stockholm=W. Europe Standard Time
Europe/Oslo=W. Europe Standard Time
Europe/Vienna=W. Europe Standard Time
Europe/Zurich=W. Europe Standard Time
Europe/Luxembourg=W. Europe Standard Time
Europe/Monaco=W. Europe Standard Time
Europe/Paris=Romance Standard Time
Europe/Brussels=Romance Standard Time
Europe/Madrid=Romance Standard Time
Europe/Copenhagen=Romance Standard Time
Europe/Budapest=Central Europe Standard Time
Europe/Prague=Central Europe Standard Time
Europe/Bratislava=Central Europe Standard Time
Europe/Belgrade=Central Europe Standard Time
Europe/Warsaw=Central European Standard Time
Europe/Zagreb=Central European Standard Time
Africa/Lagos=W. Central Africa Standard Time
Europe/Bucharest=GTB Standard Time
Europe/Athens=GTB Standard Time
Europe/Sofia=FLE Standard Time
Europe/Helsinki=FLE Standard Time
Europe/Riga=FLE Standard Time
Europe/Tallinn=FLE Standard Time
Europe/Vilnius=FLE Standard Time
Europe/Kiev=FLE Standard Time
Europe/Kyiv=FLE Standard Time
Europe/Chisinau=E. Europe Standard Time
Africa/Cairo=Egypt Standard Time
Asia/Jerusalem=Israel Standard Time
Asia/Amman=Jordan Standard Time
Asia/Beirut=Middle East Standard Time
Asia/Damascus=Syria Standard Time
Africa/Johannesburg=South Africa Standard Time
Europe/Kaliningrad=Kaliningrad Standard Time
Europe/Moscow=Russian Standard Time
Europe/Simferopol=Russian Standard Time
Europe/Minsk=Belarus Standard Time
Europe/Istanbul=Turkey Standard Time
Asia/Baghdad=Arabic Standard Time
Asia/Riyadh=Arab Standard Time
Asia/Qatar=Arab Standard Time
Asia/Kuwait=Arab Standard Time
Africa/Nairobi=E. Africa Standard Time
Asia/Tehran=Iran Standard Time
Asia/Dubai=Arabian Standard Time
Asia/Baku=Azerbaijan Standard Time
Asia/Tbilisi=Georgian Standard Time
Asia/Yerevan=Caucasus Standard Time
Europe/Samara=Russia Time Zone 3
Asia/Kabul=Afghanistan Standard Time
Asia/Tashkent=West Asia Standard Time
Asia/Yekaterinburg=Ekaterinburg Standard Time
Asia/Karachi=Pakistan Standard Time
Asia/Kolkata=India Standard Time
Asia/Calcutta=India Standard Time
Asia/Colombo=Sri Lanka Standard Time
Asia/Kathmandu=Nepal Standard Time
Asia/Katmandu=Nepal Standard Time
Asia/Almaty=Central Asia Standard Time
Asia/Dhaka=Bangladesh Standard Time
Asia/Omsk=Omsk Standard Time
Asia/Yangon=Myanmar Standard Time
Asia/Rangoon=Myanmar Standard Time
Asia/Bangkok=SE Asia Standard Time
Asia/Ho_Chi_Minh=SE Asia Standard Time
Asia/Jakarta=SE Asia Standard Time
Asia/Novosibirsk=N. Central Asia Standard Time
Asia/Krasnoyarsk=North Asia Standard Time
Asia/Shanghai=China Standard Time
Asia/Hong_Kong=China Standard Time
Asia/Macau=China Standard Time
Asia/Irkutsk=North Asia East Standard Time
Asia/Singapore=Singapore Standard Time
Asia/Kuala_Lumpur=Singapore Standard Time
Asia/Manila=Singapore Standard Time
Australia/Perth=W. Australia Standard Time
Asia/Taipei=Taipei Standard Time
Asia/Ulaanbaatar=Ulaanbaatar Standard Time
Asia/Tokyo=Tokyo Standard Time
Asia/Seoul=Korea Standard Time
Asia/Pyongyang=North Korea Standard Time
Asia/Yakutsk=Yakutsk Standard Time
Australia/Adelaide=Cen. Australia Standard Time
Australia/Darwin=AUS Central Standard Time
Australia/Brisbane=E. Australia Standard Time
Australia/Sydney=AUS Eastern Standard Time
Australia/Melbourne=AUS Eastern Standard Time
Pacific/Port_Moresby=West Pacific Standard Time
Australia/Hobart=Tasmania Standard Time
Asia/Vladivostok=Vladivostok Standard Time
Asia/Magadan=Magadan Standard Time
Asia/Sakhalin=Sakhalin Standard Time
Asia/Kamchatka=Russia Time Zone 11
Pacific/Guadalcanal=Central Pacific Standard Time
Pacific/Auckland=New Zealand Standard Time
Pacific/Fiji=Fiji Standard Time
Pacific/Chatham=Chatham Islands Standard Time
Pacific/Tongatapu=Tonga Standard Time
Pacific/Apia=Samoa Standard Time
Pacific/Kiritimati=Line Islands Standard Time
Pacific/Marquesas=Marquesas Standard Time
Australia/Eucla=Aus Central W. Standard Time
Australia/Lord_Howe=Lord Howe Standard Time
)";

struct ZonePrimary {
    QByteArray iana;
    QByteArray windows;
};

struct ZoneTable {
    QHash<QByteArray, QByteArray> exact;
    QList<ZonePrimary> primaries;
};

const ZoneTable &zoneTable()
{
    static const ZoneTable table = [] {
        ZoneTable built;
        const QList<QByteArray> lines = QByteArray(kZones).split('\n');
        for (QByteArray line : lines) {
            line = line.trimmed();
            if (line.isEmpty() || line.startsWith('#'))
                continue;
            const int eq = line.indexOf('=');
            if (eq <= 0)
                continue;
            const QByteArray iana = line.left(eq).trimmed();
            const QByteArray windows = line.mid(eq + 1).trimmed();
            if (iana.isEmpty() || windows.isEmpty() || built.exact.contains(iana))
                continue;
            built.exact.insert(iana, windows);
            bool seen = false;
            for (const ZonePrimary &primary : built.primaries) {
                if (primary.windows == windows) {
                    seen = true;
                    break;
                }
            }
            if (!seen)
                built.primaries.append(ZonePrimary{iana, windows});
        }
        return built;
    }();
    return table;
}

QString statePath()
{
    QDir().mkpath(QStringLiteral("C:/ProgramData/stopRKN"));
    return QStringLiteral("C:/ProgramData/stopRKN/privacy-state.json");
}

QString hopSignature(const QList<Proxy> &hops)
{
    QStringList parts;
    for (const Proxy &hop : hops)
        parts.append(proxyTypeKey(hop.type) + QLatin1Char('|') + hop.host + QLatin1Char('|')
                     + QString::number(hop.port));
    return parts.join(QLatin1Char(';'));
}

class ExitProbe : public QObject {
public:
    ExitProbe(QList<Proxy> hops, QObject *parent)
        : QObject(parent)
        , hops_(std::move(hops))
    {
    }

    void start()
    {
        auto *dialer = new Dialer(hops_, QStringLiteral("ip-api.com"), 80, true, this);
        connect(dialer, &Dialer::failed, this, [this](const QString &error) { finish({}, {}, {}, error); });
        connect(dialer, &Dialer::established, this, [this](Pipe *pipe) {
            pipe->setParent(this);
            connect(pipe, &Pipe::bytes, this, [this](const QByteArray &chunk) { buffer_.append(chunk); });
            connect(pipe, &Pipe::finished, this, [this](const QString &) { parse(buffer_); });
            pipe->write(QByteArrayLiteral(
                "GET /json/?fields=status,query,timezone,countryCode HTTP/1.1\r\n"
                "Host: ip-api.com\r\n"
                "Connection: close\r\n"
                "Accept: application/json\r\n"
                "User-Agent: stopRKN\r\n"
                "\r\n"));
            pipe->goLive();
            QTimer::singleShot(12000, this, [this] {
                finish({}, {}, {}, QString::fromUtf8("таймаут ответа о часовом поясе"));
            });
        });
        dialer->start();
    }

    QList<Proxy> hops_;
    QByteArray buffer_;
    std::function<void(const QString &, const QString &, const QString &, const QString &)> done;

    void parse(const QByteArray &raw)
    {
        const int begin = raw.indexOf('{');
        const int end = raw.lastIndexOf('}');
        if (begin < 0 || end < begin) {
            finish({}, {}, {}, QString::fromUtf8("ответ о часовом поясе без JSON"));
            return;
        }
        const QJsonObject obj = QJsonDocument::fromJson(raw.mid(begin, end - begin + 1)).object();
        if (obj.value(QStringLiteral("status")).toString() != QLatin1String("success")) {
            finish({}, {}, {}, QString::fromUtf8("сервис часового пояса отказал"));
            return;
        }
        finish(obj.value(QStringLiteral("timezone")).toString(), obj.value(QStringLiteral("query")).toString(),
               obj.value(QStringLiteral("countryCode")).toString(), {});
    }

    void finish(const QString &iana, const QString &ip, const QString &country, const QString &error)
    {
        if (finished_)
            return;
        finished_ = true;
        const auto cb = done;
        deleteLater();
        if (cb)
            cb(iana, ip, country, error);
    }

    bool finished_ = false;
};

#ifdef _WIN32
void enableTimeZonePrivilege()
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return;
    TOKEN_PRIVILEGES privileges{};
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (LookupPrivilegeValueW(nullptr, SE_TIME_ZONE_NAME, &privileges.Privileges[0].Luid))
        AdjustTokenPrivileges(token, FALSE, &privileges, 0, nullptr, nullptr);
    CloseHandle(token);
}

QString currentWindowsZone()
{
    DYNAMIC_TIME_ZONE_INFORMATION info{};
    if (GetDynamicTimeZoneInformation(&info) == TIME_ZONE_ID_INVALID)
        return {};
    return QString::fromWCharArray(info.TimeZoneKeyName);
}

bool readRegistryString(HKEY key, const wchar_t *name, QString *value)
{
    DWORD size = 0;
    if (RegGetValueW(key, nullptr, name, RRF_RT_REG_SZ, nullptr, nullptr, &size) != ERROR_SUCCESS || size < sizeof(wchar_t))
        return false;
    QByteArray buf(int(size), 0);
    if (RegGetValueW(key, nullptr, name, RRF_RT_REG_SZ, nullptr, buf.data(), &size) != ERROR_SUCCESS)
        return false;
    *value = QString::fromWCharArray(reinterpret_cast<const wchar_t *>(buf.constData()));
    return true;
}

bool setWindowsZone(const QString &windowsId, QString *error)
{
    if (windowsId.isEmpty()) {
        if (error)
            *error = QString::fromUtf8("пустое имя пояса");
        return false;
    }
    if (currentWindowsZone() == windowsId)
        return true;
    enableTimeZonePrivilege();
    const std::wstring keyPath = (L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Time Zones\\"
                                  + windowsId.toStdWString());
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS) {
        if (error)
            *error = QString::fromUtf8("пояс «%1» не найден в Windows").arg(windowsId);
        return false;
    }
    DWORD size = 0;
    bool tziOk = RegGetValueW(key, nullptr, L"TZI", RRF_RT_REG_BINARY, nullptr, nullptr, &size) == ERROR_SUCCESS
        && size >= 44;
    QByteArray tzi(int(size), 0);
    if (tziOk)
        tziOk = RegGetValueW(key, nullptr, L"TZI", RRF_RT_REG_BINARY, nullptr, tzi.data(), &size) == ERROR_SUCCESS
            && size >= 44;
    QString standardName;
    QString daylightName;
    readRegistryString(key, L"Std", &standardName);
    readRegistryString(key, L"Dlt", &daylightName);
    RegCloseKey(key);
    if (!tziOk) {
        if (error)
            *error = QString::fromUtf8("у пояса «%1» нет описания").arg(windowsId);
        return false;
    }

    DYNAMIC_TIME_ZONE_INFORMATION info{};
    const char *bytes = tzi.constData();
    std::memcpy(&info.Bias, bytes, 4);
    std::memcpy(&info.StandardBias, bytes + 4, 4);
    std::memcpy(&info.DaylightBias, bytes + 8, 4);
    std::memcpy(&info.StandardDate, bytes + 12, 16);
    std::memcpy(&info.DaylightDate, bytes + 28, 16);
    standardName.left(31).toWCharArray(info.StandardName);
    daylightName.left(31).toWCharArray(info.DaylightName);
    windowsId.left(127).toWCharArray(info.TimeZoneKeyName);
    if (!SetDynamicTimeZoneInformation(&info)) {
        if (error)
            *error = QString::fromUtf8("Windows не сменила пояс, код %1").arg(GetLastError());
        return false;
    }
    SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, reinterpret_cast<LPARAM>(L"intl"),
                        SMTO_ABORTIFHUNG, 200, nullptr);
    return true;
}

HKEY hiveFromName(const QString &name)
{
    return name == QLatin1String("HKCU") ? HKEY_CURRENT_USER : HKEY_LOCAL_MACHINE;
}

REGSAM viewFromInt(int view)
{
    return view == 32 ? KEY_WOW64_32KEY : KEY_WOW64_64KEY;
}

bool writePolicyValue(HKEY hive, REGSAM view, const QString &subkey, const wchar_t *valueName, const wchar_t *text,
                      bool *had, QString *previous)
{
    HKEY key = nullptr;
    const std::wstring path = subkey.toStdWString();
    if (RegCreateKeyExW(hive, path.c_str(), 0, nullptr, 0, KEY_QUERY_VALUE | KEY_SET_VALUE | view, nullptr, &key, nullptr)
        != ERROR_SUCCESS)
        return false;
    *had = false;
    previous->clear();
    DWORD size = 0;
    if (RegGetValueW(key, nullptr, valueName, RRF_RT_REG_SZ, nullptr, nullptr, &size) == ERROR_SUCCESS
        && size >= sizeof(wchar_t)) {
        QByteArray buf(int(size), 0);
        if (RegGetValueW(key, nullptr, valueName, RRF_RT_REG_SZ, nullptr, buf.data(), &size) == ERROR_SUCCESS) {
            *had = true;
            *previous = QString::fromWCharArray(reinterpret_cast<const wchar_t *>(buf.constData()));
        }
    }
    const DWORD bytes = DWORD((wcslen(text) + 1) * sizeof(wchar_t));
    const bool ok = RegSetValueExW(key, valueName, 0, REG_SZ, reinterpret_cast<const BYTE *>(text), bytes) == ERROR_SUCCESS;
    RegCloseKey(key);
    return ok;
}

bool restorePolicyValue(const QJsonObject &entry)
{
    HKEY key = nullptr;
    const std::wstring path = entry.value(QStringLiteral("key")).toString().toStdWString();
    const REGSAM view = viewFromInt(entry.value(QStringLiteral("view")).toInt(64));
    if (RegOpenKeyExW(hiveFromName(entry.value(QStringLiteral("root")).toString()), path.c_str(), 0,
                      KEY_SET_VALUE | view, &key)
        != ERROR_SUCCESS)
        return false;
    const QString valueName = entry.value(QStringLiteral("name")).toString(QStringLiteral("WebRtcIPHandling"));
    const std::wstring name = valueName.toStdWString();
    bool ok = true;
    if (entry.value(QStringLiteral("had")).toBool()) {
        const std::wstring previous = entry.value(QStringLiteral("previous")).toString().toStdWString();
        const DWORD bytes = DWORD((previous.size() + 1) * sizeof(wchar_t));
        ok = RegSetValueExW(key, name.c_str(), 0, REG_SZ, reinterpret_cast<const BYTE *>(previous.c_str()), bytes)
            == ERROR_SUCCESS;
    } else {
        const LONG err = RegDeleteValueW(key, name.c_str());
        ok = err == ERROR_SUCCESS || err == ERROR_FILE_NOT_FOUND;
    }
    RegCloseKey(key);
    return ok;
}

const wchar_t *kPolicyKeys[] = {
    L"Software\\Policies\\Google\\Chrome",
    L"Software\\Policies\\Microsoft\\Edge",
    L"Software\\Policies\\YandexBrowser",
    L"Software\\Policies\\Opera",
    L"Software\\Policies\\BraveSoftware\\Brave",
    L"Software\\Policies\\Vivaldi",
    L"Software\\Policies\\Chromium",
};

QJsonObject preferenceLock(const QJsonValue &value)
{
    QJsonObject obj;
    obj.insert(QStringLiteral("Value"), value);
    obj.insert(QStringLiteral("Status"), QStringLiteral("locked"));
    return obj;
}

QStringList firefoxDirectories()
{
    QStringList dirs;
    const auto addExe = [&dirs](const QString &exe) {
        if (exe.isEmpty())
            return;
        const QFileInfo info(exe);
        if (!info.exists())
            return;
        const QString dir = info.absolutePath();
        if (!dirs.contains(dir))
            dirs.append(dir);
    };
    const QStringList names = {
        QStringLiteral("firefox.exe"),
        QStringLiteral("librewolf.exe"),
        QStringLiteral("waterfox.exe"),
    };
    for (const QString &name : names) {
        QSettings apps(QStringLiteral("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\")
                           + name,
                       QSettings::NativeFormat);
        addExe(apps.value(QStringLiteral(".")).toString());
    }
    addExe(QStringLiteral("C:/Program Files/Mozilla Firefox/firefox.exe"));
    addExe(QStringLiteral("C:/Program Files/LibreWolf/librewolf.exe"));
    addExe(QStringLiteral("C:/Program Files/Waterfox/waterfox.exe"));
    return dirs;
}

bool writeFirefoxPolicy(const QString &dir, const QString &languages, QJsonObject *record, QString *error)
{
    const QString folder = dir + QStringLiteral("/distribution");
    if (!QDir().mkpath(folder)) {
        if (error)
            *error = folder;
        return false;
    }
    const QString path = folder + QStringLiteral("/policies.json");
    const QString backup = path + QStringLiteral(".stoprkn.bak");
    const bool created = !QFile::exists(path);
    QJsonObject root;
    if (!created) {
        QFile file(path);
        if (!file.open(QIODevice::ReadOnly)) {
            if (error)
                *error = path;
            return false;
        }
        const QByteArray raw = file.readAll();
        const QJsonDocument existing = QJsonDocument::fromJson(raw);
        if (!existing.isObject() && !raw.trimmed().isEmpty()) {
            if (error)
                *error = path;
            return false;
        }
        root = existing.object();
        if (!QFile::exists(backup) && !QFile::copy(path, backup)) {
            if (error)
                *error = path;
            return false;
        }
    }
    QJsonObject policies = root.value(QStringLiteral("policies")).toObject();
    QJsonObject prefs = policies.value(QStringLiteral("Preferences")).toObject();
    prefs.insert(QStringLiteral("media.peerconnection.ice.proxy_only"), preferenceLock(true));
    prefs.insert(QStringLiteral("media.peerconnection.ice.no_host"), preferenceLock(true));
    prefs.insert(QStringLiteral("network.trr.mode"), preferenceLock(3));
    prefs.insert(QStringLiteral("network.trr.uri"), preferenceLock(QStringLiteral("https://cloudflare-dns.com/dns-query")));
    prefs.insert(QStringLiteral("network.trr.bootstrapAddress"), preferenceLock(QStringLiteral("1.1.1.1")));
    if (!languages.isEmpty())
        prefs.insert(QStringLiteral("intl.accept_languages"), preferenceLock(languages));
    policies.insert(QStringLiteral("Preferences"), prefs);
    root.insert(QStringLiteral("policies"), policies);
    QSaveFile out(path);
    if (!out.open(QIODevice::WriteOnly) || out.write(QJsonDocument(root).toJson(QJsonDocument::Indented)) < 0
        || !out.commit()) {
        if (error)
            *error = path;
        return false;
    }
    record->insert(QStringLiteral("path"), path);
    record->insert(QStringLiteral("created"), created);
    record->insert(QStringLiteral("backup"), created ? QString() : backup);
    return true;
}

bool restoreFirefoxPolicy(const QJsonObject &entry)
{
    const QString path = entry.value(QStringLiteral("path")).toString();
    const QString backup = entry.value(QStringLiteral("backup")).toString();
    if (path.isEmpty())
        return true;
    if (entry.value(QStringLiteral("created")).toBool() || backup.isEmpty()) {
        QFile::remove(path);
        return true;
    }
    QFile::remove(path);
    if (!QFile::copy(backup, path))
        return false;
    QFile::remove(backup);
    return true;
}
#endif

} // namespace

QString acceptLanguagesForCountry(const QString &country)
{
    const QString code = country.trimmed().toUpper();
    if (code == QLatin1String("GB") || code == QLatin1String("IE"))
        return QStringLiteral("en-GB, en");
    if (code == QLatin1String("US") || code == QLatin1String("AU") || code == QLatin1String("NZ"))
        return QStringLiteral("en-US, en");
    if (code == QLatin1String("CA"))
        return QStringLiteral("en-CA, en");
    if (code == QLatin1String("DE") || code == QLatin1String("AT"))
        return QStringLiteral("de-DE, de, en-US, en");
    if (code == QLatin1String("FR"))
        return QStringLiteral("fr-FR, fr, en-US, en");
    if (code == QLatin1String("NL"))
        return QStringLiteral("nl-NL, nl, en-US, en");
    if (code == QLatin1String("ES"))
        return QStringLiteral("es-ES, es, en-US, en");
    if (code == QLatin1String("IT"))
        return QStringLiteral("it-IT, it, en-US, en");
    if (code == QLatin1String("BR"))
        return QStringLiteral("pt-BR, pt, en-US, en");
    if (code == QLatin1String("JP"))
        return QStringLiteral("ja-JP, ja, en-US, en");
    if (code == QLatin1String("RU") || code == QLatin1String("BY") || code == QLatin1String("KZ"))
        return QStringLiteral("ru-RU, ru, en-US, en");
    if (code.isEmpty())
        return {};
    return QStringLiteral("en-US, en");
}

QString windowsZoneForIana(const QByteArray &iana)
{
    const QByteArray key = iana.trimmed();
    if (key.isEmpty())
        return {};
    const ZoneTable &table = zoneTable();
    const auto found = table.exact.constFind(key);
    if (found != table.exact.cend())
        return QString::fromLatin1(found.value());
    const QTimeZone want(key);
    if (!want.isValid())
        return {};
    const QDateTime now = QDateTime::currentDateTimeUtc();
    const int offset = want.offsetFromUtc(now);
    const int slash = key.indexOf('/');
    const QByteArray region = slash > 0 ? key.left(slash) : key;
    QByteArray best;
    int bestScore = -1;
    for (const ZonePrimary &primary : table.primaries) {
        const QTimeZone zone(primary.iana);
        if (!zone.isValid() || zone.offsetFromUtc(now) != offset)
            continue;
        int score = 1;
        if (primary.iana.startsWith(region)
            && (primary.iana.size() == region.size() || primary.iana.at(region.size()) == '/'))
            score += 2;
        if (score > bestScore) {
            bestScore = score;
            best = primary.windows;
        }
    }
    return QString::fromLatin1(best);
}

class PrivacyGuard::Private {
public:
    QString originalZone;
    QString appliedZone;
    QJsonArray chromium;
    QJsonArray firefox;
    bool loaded = false;
    QString hopSig;
    bool zoneReady = false;
    bool probeBusy = false;
    int probeGen = 0;
    int attempts = 0;
    bool webrtcReady = false;
    bool loggedNoRule = false;
    QList<Proxy> hops;

    bool empty() const
    {
        return originalZone.isEmpty() && appliedZone.isEmpty() && chromium.isEmpty() && firefox.isEmpty();
    }

    void load()
    {
        if (loaded)
            return;
        loaded = true;
        QFile file(statePath());
        if (!file.open(QIODevice::ReadOnly))
            return;
        const QJsonObject root = QJsonDocument::fromJson(file.readAll()).object();
        originalZone = root.value(QStringLiteral("originalZone")).toString();
        appliedZone = root.value(QStringLiteral("appliedZone")).toString();
        chromium = root.value(QStringLiteral("chromium")).toArray();
        firefox = root.value(QStringLiteral("firefox")).toArray();
        webrtcReady = !chromium.isEmpty() || !firefox.isEmpty();
        zoneReady = !appliedZone.isEmpty();
    }

    void save() const
    {
        const QString path = statePath();
        if (empty()) {
            QFile::remove(path);
            return;
        }
        QJsonObject root;
        root.insert(QStringLiteral("originalZone"), originalZone);
        root.insert(QStringLiteral("appliedZone"), appliedZone);
        root.insert(QStringLiteral("chromium"), chromium);
        root.insert(QStringLiteral("firefox"), firefox);
        QSaveFile file(path);
        if (!file.open(QIODevice::WriteOnly))
            return;
        file.write(QJsonDocument(root).toJson(QJsonDocument::Compact));
        file.commit();
    }
};

PrivacyGuard::PrivacyGuard(QObject *parent)
    : QObject(parent)
    , d_(new Private)
{
}

PrivacyGuard::~PrivacyGuard()
{
    delete d_;
}

void PrivacyGuard::recoverIfIdle(bool routingOff)
{
    if (!routingOff)
        return;
    d_->load();
    if (d_->empty())
        return;
    sync(AppConfig{}, false);
}

void PrivacyGuard::restoreWebrtc()
{
#ifdef _WIN32
    QJsonArray chromiumLeft;
    for (const QJsonValue &value : d_->chromium) {
        if (!restorePolicyValue(value.toObject()))
            chromiumLeft.append(value);
    }
    d_->chromium = chromiumLeft;
    QJsonArray firefoxLeft;
    for (const QJsonValue &value : d_->firefox) {
        if (!restoreFirefoxPolicy(value.toObject()))
            firefoxLeft.append(value);
    }
    d_->firefox = firefoxLeft;
#endif
    d_->webrtcReady = !d_->chromium.isEmpty() || !d_->firefox.isEmpty();
    d_->save();
}

void PrivacyGuard::restoreTimezone()
{
    ++d_->probeGen;
    d_->probeBusy = false;
    d_->attempts = 0;
    d_->hopSig.clear();
    d_->zoneReady = false;
    if (d_->originalZone.isEmpty() && d_->appliedZone.isEmpty())
        return;
#ifdef _WIN32
    if (!d_->originalZone.isEmpty()) {
        QString error;
        if (!setWindowsZone(d_->originalZone, &error)) {
            Logger::instance()->error(QString::fromUtf8("Не вернул часовой пояс: %1").arg(error));
            d_->save();
            return;
        }
        Logger::instance()->info(QString::fromUtf8("Часовой пояс Windows возвращён: %1").arg(d_->originalZone));
    }
#endif
    d_->originalZone.clear();
    d_->appliedZone.clear();
    d_->save();
}

void PrivacyGuard::applyWebrtc()
{
    if (d_->webrtcReady)
        return;
#ifdef _WIN32
    const HKEY hives[] = {HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    const char *hiveNames[] = {"HKCU", "HKLM"};
    const int views[] = {64, 32};
    for (int hive = 0; hive < 2; ++hive) {
        for (int view : views) {
            for (const wchar_t *subkey : kPolicyKeys) {
                const struct {
                    const wchar_t *name;
                    const wchar_t *text;
                } values[] = {
                    {L"WebRtcIPHandling", L"disable_non_proxied_udp"},
                    {L"DnsOverHttpsMode", L"secure"},
                    {L"DnsOverHttpsTemplates", L"https://cloudflare-dns.com/dns-query"},
                };
                for (const auto &value : values) {
                    bool had = false;
                    QString previous;
                    if (!writePolicyValue(hives[hive], viewFromInt(view), QString::fromWCharArray(subkey), value.name,
                                          value.text, &had, &previous))
                        continue;
                    if (had && previous == QString::fromWCharArray(value.text))
                        continue;
                    QJsonObject entry;
                    entry.insert(QStringLiteral("root"), QString::fromLatin1(hiveNames[hive]));
                    entry.insert(QStringLiteral("view"), view);
                    entry.insert(QStringLiteral("key"), QString::fromWCharArray(subkey));
                    entry.insert(QStringLiteral("name"), QString::fromWCharArray(value.name));
                    entry.insert(QStringLiteral("had"), had);
                    entry.insert(QStringLiteral("previous"), previous);
                    d_->chromium.append(entry);
                }
            }
        }
    }
    QString firefoxError;
    for (const QString &dir : firefoxDirectories()) {
        QJsonObject record;
        if (writeFirefoxPolicy(dir, QString(), &record, &firefoxError))
            d_->firefox.append(record);
    }
    d_->webrtcReady = true;
    d_->save();
    if (d_->chromium.isEmpty() && d_->firefox.isEmpty())
        Logger::instance()->warn(QString::fromUtf8(
            "Политики браузеров не записались. UDP WebRTC всё равно отбрасывается, локальный адрес в обход политики может остаться."));
    else
        Logger::instance()->info(QString::fromUtf8(
            "WebRTC закрыт, DNS браузера идёт через Cloudflare по прокси. Закройте браузер и откройте снова."));
    if (!firefoxError.isEmpty())
        Logger::instance()->warn(QString::fromUtf8("Политику Firefox не записал: %1").arg(firefoxError));
#else
    d_->webrtcReady = true;
#endif
}

void PrivacyGuard::sync(const AppConfig &config, bool active)
{
    d_->load();
    if (!active || !config.routingEnabled) {
        d_->loggedNoRule = false;
        restoreWebrtc();
        restoreTimezone();
        return;
    }

    if (config.blockWebrtc)
        applyWebrtc();
    else if (d_->webrtcReady)
        restoreWebrtc();

    if (!config.matchTimezone) {
        d_->loggedNoRule = false;
        restoreTimezone();
        return;
    }

    const QList<Proxy> hops = timezoneExitHops(config);
    if (hops.isEmpty()) {
        if (!d_->loggedNoRule) {
            d_->loggedNoRule = true;
            Logger::instance()->info(QString::fromUtf8(
                "Часовой пояс не меняю: нет правила, которое отправляет весь трафик браузера в прокси. "
                "Иначе прямые сайты увидят чужое время при своём IP."));
        }
        restoreTimezone();
        return;
    }
    d_->loggedNoRule = false;
    const QString signature = hopSignature(hops);
    if (d_->probeBusy)
        return;
    if (d_->zoneReady && signature == d_->hopSig)
        return;
    d_->hops = hops;
    d_->hopSig = signature;
    d_->zoneReady = false;
    d_->attempts = 0;
    d_->probeBusy = true;
    const int gen = ++d_->probeGen;
    auto *probe = new ExitProbe(hops, this);
    QPointer<PrivacyGuard> self(this);
    probe->done = [self, gen](const QString &iana, const QString &ip, const QString &country, const QString &error) {
        if (!self || gen != self->d_->probeGen)
            return;
        self->d_->probeBusy = false;
        self->onExit(gen, iana, ip, country, error);
    };
    probe->start();
}

void PrivacyGuard::applyExitLanguage(const QString &country)
{
    const QString languages = acceptLanguagesForCountry(country);
    if (languages.isEmpty())
        return;
#ifdef _WIN32
    QStringList dirs;
    for (const QJsonValue &value : d_->firefox) {
        const QString path = value.toObject().value(QStringLiteral("path")).toString();
        QDir dir = QFileInfo(path).dir();
        if (dir.dirName().compare(QLatin1String("distribution"), Qt::CaseInsensitive) != 0 || !dir.cdUp())
            continue;
        const QString installDir = dir.absolutePath();
        if (!dirs.contains(installDir))
            dirs.append(installDir);
    }
    if (dirs.isEmpty())
        dirs = firefoxDirectories();
    QString error;
    for (const QString &dir : dirs) {
        QJsonObject record;
        if (!writeFirefoxPolicy(dir, languages, &record, &error))
            continue;
        bool known = false;
        for (const QJsonValue &value : d_->firefox) {
            if (value.toObject().value(QStringLiteral("path")).toString() == record.value(QStringLiteral("path")).toString()) {
                known = true;
                break;
            }
        }
        if (!known)
            d_->firefox.append(record);
    }
    d_->save();
    if (!error.isEmpty())
        Logger::instance()->warn(QString::fromUtf8("Язык Firefox не записал: %1").arg(error));
    else
        Logger::instance()->info(QString::fromUtf8(
            "Для сайтов язык браузера: %1. Окно Firefox остаётся как было. Откройте его заново.").arg(languages));
#else
    Q_UNUSED(languages);
#endif
}

void PrivacyGuard::onExit(int generation, const QString &iana, const QString &ip, const QString &country,
                          const QString &error)
{
    if (generation != d_->probeGen)
        return;
    if (!error.isEmpty() || iana.isEmpty()) {
        Logger::instance()->warn(QString::fromUtf8("Часовой пояс выхода не узнали: %1")
                                     .arg(error.isEmpty() ? iana : error));
        if (d_->attempts < 2) {
            ++d_->attempts;
            const int gen = d_->probeGen;
            QTimer::singleShot(15000, this, [this, gen] {
                if (gen != d_->probeGen || d_->hops.isEmpty())
                    return;
                d_->probeBusy = true;
                const int next = ++d_->probeGen;
                auto *probe = new ExitProbe(d_->hops, this);
                QPointer<PrivacyGuard> self(this);
                probe->done = [self, next](const QString &iana, const QString &ip, const QString &country, const QString &err) {
                    if (!self || next != self->d_->probeGen)
                        return;
                    self->d_->probeBusy = false;
                    self->onExit(next, iana, ip, country, err);
                };
                probe->start();
            });
        }
        return;
    }
    applyExitLanguage(country);
    const QString windows = windowsZoneForIana(iana.toUtf8());
    if (windows.isEmpty()) {
        Logger::instance()->warn(QString::fromUtf8("Для пояса %1 нет соответствия в Windows").arg(iana));
        return;
    }
#ifdef _WIN32
    if (d_->originalZone.isEmpty()) {
        d_->originalZone = currentWindowsZone();
        if (d_->originalZone.isEmpty()) {
            Logger::instance()->error(QString::fromUtf8("Не прочитал текущий часовой пояс Windows"));
            return;
        }
        d_->save();
    }
    QString failure;
    if (!setWindowsZone(windows, &failure)) {
        Logger::instance()->error(failure);
        return;
    }
    d_->appliedZone = windows;
    d_->zoneReady = true;
    d_->save();
    Logger::instance()->info(QString::fromUtf8("Часы Windows: сейчас %1, выход %2 (%3). Было %4. Браузер нужно открыть заново.")
                                 .arg(windows, ip, iana, d_->originalZone));
#else
    Q_UNUSED(ip);
    d_->appliedZone = windows;
    d_->zoneReady = true;
#endif
}

} // namespace qpr
