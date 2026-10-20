#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef _WIN32_WINNT
#    define _WIN32_WINNT 0x0601
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
#  include <iphlpapi.h>
#  include <wininet.h>
#  include <winsvc.h>
#endif

#include "platform.h"

#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QFileInfo>
#include <QHash>
#include <QMutex>
#include <QMutexLocker>
#include <QSettings>

#include <cstring>
#include <string>

namespace qpr {
namespace {

#ifdef Q_OS_WIN
QString nameFromPid(quint32 pid)
{
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process)
        return QString::fromUtf8("pid %1").arg(pid);
    WCHAR buffer[1024];
    DWORD size = 1024;
    QString name = QString::fromUtf8("pid %1").arg(pid);
    if (QueryFullProcessImageNameW(process, 0, buffer, &size))
        name = QFileInfo(QString::fromWCharArray(buffer, int(size))).fileName();
    CloseHandle(process);
    return name;
}
#endif

QSettings runSettings()
{
    return QSettings(QStringLiteral("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
                     QSettings::NativeFormat);
}

#ifdef Q_OS_WIN
ProcInfo lookupIpv6(const QHostAddress &address, quint16 port, quint16 localPort, bool refresh)
{
    struct Row {
        unsigned char addr[16]{};
        quint16 local = 0;
        quint16 remote = 0;
        quint32 pid = 0;
        DWORD state = 0;
    };
    static QList<Row> cache;
    static qint64 cachedAt = 0;
    static QHash<quint32, QString> names;
    const Q_IPV6ADDR ip = address.toIPv6Address();

    const auto reload = [&] {
        DWORD size = 0;
        GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
        if (size == 0)
            return;
        QByteArray buffer(int(size) + 4096, 0);
        size = DWORD(buffer.size());
        auto *table = reinterpret_cast<MIB_TCP6TABLE_OWNER_PID *>(buffer.data());
        if (GetExtendedTcpTable(table, &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR)
            return;
        QList<Row> fresh;
        fresh.reserve(int(table->dwNumEntries));
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            const MIB_TCP6ROW_OWNER_PID &row = table->table[i];
            Row item;
            std::memcpy(item.addr, row.ucLocalAddr, 16);
            item.local = ntohs(static_cast<u_short>(row.dwLocalPort));
            item.remote = ntohs(static_cast<u_short>(row.dwRemotePort));
            item.pid = row.dwOwningPid;
            item.state = row.dwState;
            fresh.append(item);
        }
        cache = fresh;
        cachedAt = QDateTime::currentMSecsSinceEpoch();
    };

    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    if (refresh || cache.isEmpty() || now - cachedAt > 200)
        reload();

    const auto take = [&](quint32 pid, ProcInfo *info) {
        info->pid = pid;
        if (!names.contains(pid))
            names.insert(pid, nameFromPid(pid));
        info->name = names.value(pid);
    };
    const auto match = [&](bool strict, bool anyAddr, ProcInfo *info) {
        const quint32 self = GetCurrentProcessId();
        ProcInfo ours;
        bool haveOurs = false;
        for (const Row &row : cache) {
            if (row.state == MIB_TCP_STATE_LISTEN || row.state == MIB_TCP_STATE_TIME_WAIT)
                continue;
            if (row.local != port)
                continue;
            if (!anyAddr && std::memcmp(row.addr, ip.c, 16) != 0)
                continue;
            if (strict && localPort != 0 && row.remote != localPort)
                continue;
            ProcInfo candidate;
            take(row.pid, &candidate);
            if (candidate.pid != self) {
                *info = candidate;
                return true;
            }
            ours = candidate;
            haveOurs = true;
        }
        if (!haveOurs)
            return false;
        *info = ours;
        return true;
    };

    ProcInfo info;
    if (match(true, false, &info))
        return info;
    reload();
    if (match(true, false, &info) || match(false, false, &info) || match(true, true, &info))
        return info;
    return {};
}
#endif

} // namespace

ProcInfo processForUdp(quint16 localPort, bool ipv6, bool refresh)
{
#ifdef Q_OS_WIN
    struct Row {
        quint16 local = 0;
        quint32 pid = 0;
        bool v6 = false;
    };
    static QMutex mutex;
    static QList<Row> cache;
    static qint64 cachedAt = 0;
    static QHash<quint32, QString> names;
    QMutexLocker lock(&mutex);

    const auto reload = [&] {
        QList<Row> fresh;
        DWORD size = 0;
        GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
        if (size != 0) {
            QByteArray buffer(int(size) + 4096, 0);
            size = DWORD(buffer.size());
            auto *table = reinterpret_cast<MIB_UDPTABLE_OWNER_PID *>(buffer.data());
            if (GetExtendedUdpTable(table, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
                fresh.reserve(int(table->dwNumEntries));
                for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                    Row item;
                    item.local = ntohs(static_cast<u_short>(table->table[i].dwLocalPort));
                    item.pid = table->table[i].dwOwningPid;
                    fresh.append(item);
                }
            }
        }
        size = 0;
        GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
        if (size != 0) {
            QByteArray buffer(int(size) + 4096, 0);
            size = DWORD(buffer.size());
            auto *table = reinterpret_cast<MIB_UDP6TABLE_OWNER_PID *>(buffer.data());
            if (GetExtendedUdpTable(table, &size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
                for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                    Row item;
                    item.local = ntohs(static_cast<u_short>(table->table[i].dwLocalPort));
                    item.pid = table->table[i].dwOwningPid;
                    item.v6 = true;
                    fresh.append(item);
                }
            }
        }
        cache = fresh;
        cachedAt = QDateTime::currentMSecsSinceEpoch();
    };

    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    if (refresh || cache.isEmpty() || now - cachedAt > 200)
        reload();
    const auto find = [&](ProcInfo *info) {
        const quint32 self = GetCurrentProcessId();
        ProcInfo ours;
        bool haveOurs = false;
        for (const Row &row : cache) {
            if (row.local != localPort || row.v6 != ipv6)
                continue;
            ProcInfo candidate;
            candidate.pid = row.pid;
            if (!names.contains(row.pid))
                names.insert(row.pid, nameFromPid(row.pid));
            candidate.name = names.value(row.pid);
            if (candidate.pid != self) {
                *info = candidate;
                return true;
            }
            ours = candidate;
            haveOurs = true;
        }
        if (!haveOurs)
            return false;
        *info = ours;
        return true;
    };
    ProcInfo info;
    if (find(&info))
        return info;
    reload();
    if (find(&info))
        return info;
    return {};
#else
    Q_UNUSED(localPort);
    Q_UNUSED(ipv6);
    Q_UNUSED(refresh);
    return {};
#endif
}

QString processNameForPid(quint32 pid)
{
#ifdef Q_OS_WIN
    if (pid == 0)
        return {};
    static QMutex mutex;
    static QHash<quint32, QString> names;
    QMutexLocker lock(&mutex);
    if (!names.contains(pid))
        names.insert(pid, nameFromPid(pid));
    return names.value(pid);
#else
    Q_UNUSED(pid);
    return {};
#endif
}

ProcInfo processForPeer(const QHostAddress &address, quint16 port, quint16 localPort, bool refresh)
{
#ifdef Q_OS_WIN
    static QMutex tableMutex;
    QMutexLocker tableLock(&tableMutex);
    struct Row {
        quint32 addr = 0;
        quint16 local = 0;
        quint16 remote = 0;
        quint32 pid = 0;
        DWORD state = 0;
    };
    static QList<Row> cache;
    static qint64 cachedAt = 0;
    static QHash<quint32, QString> names;

    if (port == 0)
        return {};
    bool ok = false;
    const quint32 ipv4 = address.toIPv4Address(&ok);
    if (!ok)
        return lookupIpv6(address, port, localPort, refresh);

    const auto reload = [&] {
        DWORD size = 0;
        GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (size == 0)
            return;
        QByteArray buffer(int(size) + 4096, 0);
        size = DWORD(buffer.size());
        auto *table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID *>(buffer.data());
        if (GetExtendedTcpTable(table, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR)
            return;
        QList<Row> fresh;
        fresh.reserve(int(table->dwNumEntries));
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            const MIB_TCPROW_OWNER_PID &row = table->table[i];
            Row item;
            item.addr = ntohl(row.dwLocalAddr);
            item.local = ntohs(static_cast<u_short>(row.dwLocalPort));
            item.remote = ntohs(static_cast<u_short>(row.dwRemotePort));
            item.pid = row.dwOwningPid;
            item.state = row.dwState;
            fresh.append(item);
        }
        cache = fresh;
        cachedAt = QDateTime::currentMSecsSinceEpoch();
    };

    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    if (refresh || cache.isEmpty() || now - cachedAt > 200)
        reload();

    const auto match = [&](bool strict, bool anyAddr, ProcInfo *info) {
        const quint32 self = GetCurrentProcessId();
        ProcInfo ours;
        bool haveOurs = false;
        for (const Row &row : cache) {
            if (row.state == MIB_TCP_STATE_LISTEN || row.state == MIB_TCP_STATE_TIME_WAIT)
                continue;
            if (row.local != port)
                continue;
            if (!anyAddr && row.addr != ipv4)
                continue;
            if (strict && localPort != 0 && row.remote != localPort)
                continue;
            ProcInfo candidate;
            candidate.pid = row.pid;
            if (!names.contains(candidate.pid))
                names.insert(candidate.pid, nameFromPid(candidate.pid));
            candidate.name = names.value(candidate.pid);
            if (candidate.pid != self) {
                *info = candidate;
                return true;
            }
            ours = candidate;
            haveOurs = true;
        }
        if (!haveOurs)
            return false;
        *info = ours;
        return true;
    };

    ProcInfo info;
    if (match(true, false, &info))
        return info;
    reload();
    if (match(true, false, &info) || match(false, false, &info) || match(true, true, &info))
        return info;
#else
    Q_UNUSED(address);
    Q_UNUSED(port);
    Q_UNUSED(localPort);
    Q_UNUSED(refresh);
#endif
    return {};
}

void setAutostart(bool enabled)
{
#ifdef Q_OS_WIN
    QSettings run = runSettings();
    if (enabled) {
        const QString path = QDir::toNativeSeparators(QCoreApplication::applicationFilePath());
        run.remove(QStringLiteral("myIPproxy"));
        run.setValue(QStringLiteral("stopRKN"), QStringLiteral("\"%1\"").arg(path));
    } else {
        run.remove(QStringLiteral("myIPproxy"));
        run.remove(QStringLiteral("stopRKN"));
    }
#else
    Q_UNUSED(enabled);
#endif
}

bool autostartEnabled()
{
#ifdef Q_OS_WIN
    return runSettings().contains(QStringLiteral("stopRKN"));
#else
    return false;
#endif
}

namespace {

#ifdef Q_OS_WIN
QString serviceBinary()
{
    const QString path = QDir::toNativeSeparators(QCoreApplication::applicationFilePath());
    return QStringLiteral("\"%1\" --service").arg(path);
}

QString serviceError()
{
    return QString::fromUtf8("код %1").arg(GetLastError());
}
#endif

} // namespace

bool proxyServiceRunning()
{
#ifdef Q_OS_WIN
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm)
        return false;
    SC_HANDLE service = OpenServiceW(scm, L"stopRKN", SERVICE_QUERY_STATUS);
    if (!service) {
        CloseServiceHandle(scm);
        return false;
    }
    SERVICE_STATUS_PROCESS state{};
    DWORD bytes = 0;
    const BOOL ok = QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                                         reinterpret_cast<BYTE *>(&state), sizeof(state), &bytes);
    const bool running = ok && state.dwCurrentState == SERVICE_RUNNING;
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return running;
#else
    return false;
#endif
}

bool installProxyService(QString *error)
{
#ifdef Q_OS_WIN
    const std::wstring binary = serviceBinary().toStdWString();
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) {
        if (error)
            *error = serviceError();
        return false;
    }
    SC_HANDLE old = OpenServiceW(scm, L"myIPproxy", SERVICE_STOP | DELETE);
    if (old) {
        SERVICE_STATUS status{};
        ControlService(old, SERVICE_CONTROL_STOP, &status);
        DeleteService(old);
        CloseServiceHandle(old);
    }
    SC_HANDLE service = CreateServiceW(scm, L"stopRKN", L"stopRKN", SERVICE_ALL_ACCESS,
                                       SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                                       binary.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!service && GetLastError() == ERROR_SERVICE_EXISTS) {
        service = OpenServiceW(scm, L"stopRKN", SERVICE_ALL_ACCESS);
        if (service) {
            ChangeServiceConfigW(service, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                                 binary.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr, L"stopRKN");
        }
    }
    if (!service) {
        if (error)
            *error = serviceError();
        CloseServiceHandle(scm);
        return false;
    }
    if (!StartServiceW(service, 0, nullptr) && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
        if (error)
            *error = serviceError();
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return false;
    }
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return true;
#else
    Q_UNUSED(error);
    return false;
#endif
}

bool uninstallProxyService(QString *error)
{
#ifdef Q_OS_WIN
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) {
        if (error)
            *error = serviceError();
        return false;
    }
    SC_HANDLE service = OpenServiceW(scm, L"stopRKN", SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
    if (!service) {
        CloseServiceHandle(scm);
        return GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST;
    }
    SERVICE_STATUS status{};
    ControlService(service, SERVICE_CONTROL_STOP, &status);
    const bool ok = DeleteService(service);
    if (!ok && error)
        *error = serviceError();
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return ok;
#else
    Q_UNUSED(error);
    return false;
#endif
}

void SystemProxy::publish() const
{
#ifdef Q_OS_WIN
    InternetSetOptionW(nullptr, INTERNET_OPTION_SETTINGS_CHANGED, nullptr, 0);
    InternetSetOptionW(nullptr, INTERNET_OPTION_REFRESH, nullptr, 0);
#endif
}

bool SystemProxy::enable(const QString &host, quint16 port)
{
#ifdef Q_OS_WIN
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
                      L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
                      0, KEY_QUERY_VALUE | KEY_SET_VALUE, &key) != ERROR_SUCCESS)
        return false;
    if (!active_) {
        DWORD type = 0;
        DWORD enable = 0;
        DWORD size = sizeof(enable);
        if (RegQueryValueExW(key, L"ProxyEnable", nullptr, &type, reinterpret_cast<BYTE *>(&enable), &size) == ERROR_SUCCESS
            && type == REG_DWORD)
            oldEnable_ = int(enable);
        WCHAR buffer[1024];
        size = sizeof(buffer);
        type = 0;
        if (RegQueryValueExW(key, L"ProxyServer", nullptr, &type, reinterpret_cast<BYTE *>(buffer), &size) == ERROR_SUCCESS
            && type == REG_SZ)
            oldServer_ = QString::fromWCharArray(buffer);
        size = sizeof(buffer);
        type = 0;
        const LSTATUS overrideStatus = RegQueryValueExW(key, L"ProxyOverride", nullptr, &type,
                                                        reinterpret_cast<BYTE *>(buffer), &size);
        haveOldOverride_ = overrideStatus == ERROR_SUCCESS && type == REG_SZ;
        if (haveOldOverride_)
            oldOverride_ = QString::fromWCharArray(buffer);
        active_ = true;
    }
    const DWORD enabled = 1;
    const QString server = QStringLiteral("%1:%2").arg(host).arg(port);
    const std::wstring serverWide = server.toStdWString();
    const std::wstring overrideWide = std::wstring(L"localhost;127.0.0.1;<local>");
    const bool ok = RegSetValueExW(key, L"ProxyEnable", 0, REG_DWORD,
                                   reinterpret_cast<const BYTE *>(&enabled), sizeof(enabled)) == ERROR_SUCCESS
        && RegSetValueExW(key, L"ProxyServer", 0, REG_SZ,
                          reinterpret_cast<const BYTE *>(serverWide.c_str()),
                          DWORD((serverWide.size() + 1) * sizeof(wchar_t))) == ERROR_SUCCESS
        && RegSetValueExW(key, L"ProxyOverride", 0, REG_SZ,
                          reinterpret_cast<const BYTE *>(overrideWide.c_str()),
                          DWORD((overrideWide.size() + 1) * sizeof(wchar_t))) == ERROR_SUCCESS;
    RegCloseKey(key);
    if (ok)
        publish();
    return ok;
#else
    Q_UNUSED(host);
    Q_UNUSED(port);
    return false;
#endif
}

void SystemProxy::restore()
{
#ifdef Q_OS_WIN
    if (!active_)
        return;
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
                      L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
                      0, KEY_SET_VALUE, &key) != ERROR_SUCCESS) {
        active_ = false;
        return;
    }
    const DWORD enabled = DWORD(oldEnable_);
    RegSetValueExW(key, L"ProxyEnable", 0, REG_DWORD, reinterpret_cast<const BYTE *>(&enabled), sizeof(enabled));
    const std::wstring server = oldServer_.toStdWString();
    RegSetValueExW(key, L"ProxyServer", 0, REG_SZ, reinterpret_cast<const BYTE *>(server.c_str()),
                   DWORD((server.size() + 1) * sizeof(wchar_t)));
    if (haveOldOverride_) {
        const std::wstring overrideText = oldOverride_.toStdWString();
        RegSetValueExW(key, L"ProxyOverride", 0, REG_SZ, reinterpret_cast<const BYTE *>(overrideText.c_str()),
                       DWORD((overrideText.size() + 1) * sizeof(wchar_t)));
    } else {
        RegDeleteValueW(key, L"ProxyOverride");
    }
    RegCloseKey(key);
    active_ = false;
    publish();
#endif
}

} // namespace qpr
