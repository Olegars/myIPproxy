#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef _WIN32_WINNT
#    define _WIN32_WINNT 0x0601
#  endif
#  include <windows.h>
#  include <winsvc.h>
#endif

#include "core/engine.h"
#include "core/hub.h"
#include "core/logger.h"
#include "core/platform.h"

#include <QCoreApplication>
#include <QNetworkProxy>
#include <QNetworkProxyFactory>

namespace qpr {
namespace {

#ifdef _WIN32
SERVICE_STATUS_HANDLE g_status = nullptr;
SERVICE_STATUS g_state{};
QCoreApplication *g_app = nullptr;

void report(DWORD state)
{
    g_state.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_state.dwCurrentState = state;
    g_state.dwControlsAccepted = (state == SERVICE_START_PENDING) ? 0 : (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN);
    g_state.dwWin32ExitCode = NO_ERROR;
    g_state.dwWaitHint = state == SERVICE_STOP_PENDING ? 4000 : 0;
    if (g_status)
        SetServiceStatus(g_status, &g_state);
}

void WINAPI onControl(DWORD code)
{
    if (code == SERVICE_CONTROL_STOP || code == SERVICE_CONTROL_SHUTDOWN) {
        report(SERVICE_STOP_PENDING);
        if (g_app)
            QMetaObject::invokeMethod(g_app, "quit", Qt::QueuedConnection);
    }
}

void WINAPI serviceMain(DWORD, LPWSTR *)
{
    wchar_t name[] = L"stopRKN";
    g_status = RegisterServiceCtrlHandlerW(name, onControl);
    report(SERVICE_START_PENDING);
    int argc = 1;
    char arg0[] = "stopRKN";
    char *argv[] = {arg0, nullptr};
    QCoreApplication app(argc, argv);
    g_app = &app;
    QCoreApplication::setOrganizationName(QStringLiteral("stopRKN"));
    QCoreApplication::setApplicationName(QStringLiteral("stopRKN"));
    QNetworkProxy::setApplicationProxy(QNetworkProxy::NoProxy);
    QNetworkProxyFactory::setUseSystemConfiguration(false);
    Engine engine;
    engine.setServiceMode(true);
    engine.load();
    engine.start();
    HubServer hub(&engine);
    hub.start();
    Logger::instance()->info(QString::fromUtf8("Служба stopRKN запущена"));
    report(SERVICE_RUNNING);
    app.exec();
    engine.stop();
    g_app = nullptr;
    report(SERVICE_STOPPED);
}
#endif

} // namespace

int runService()
{
#ifdef _WIN32
    wchar_t name[] = L"stopRKN";
    SERVICE_TABLE_ENTRYW table[] = {
        {name, serviceMain},
        {nullptr, nullptr},
    };
    if (!StartServiceCtrlDispatcherW(table))
        return int(GetLastError());
    return 0;
#else
    return 1;
#endif
}

int installServiceCommand()
{
    int argc = 1;
    char arg0[] = "stopRKN";
    char *argv[] = {arg0, nullptr};
    QCoreApplication app(argc, argv);
    QString error;
    return installProxyService(&error) ? 0 : 1;
}

int uninstallServiceCommand()
{
    int argc = 1;
    char arg0[] = "stopRKN";
    char *argv[] = {arg0, nullptr};
    QCoreApplication app(argc, argv);
    QString error;
    return uninstallProxyService(&error) ? 0 : 1;
}

} // namespace qpr
