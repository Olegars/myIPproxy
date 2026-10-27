#include "core/crashlog.h"
#include "core/platform.h"
#include "mainwindow.h"
#include "service.h"

#include <QApplication>
#include <QIcon>
#include <QNetworkProxy>

int main(int argc, char *argv[])
{
    qpr::CrashLog::install();
    for (int i = 1; i < argc; ++i) {
        const QString arg = QString::fromLocal8Bit(argv[i]);
        if (arg == QLatin1String("--service"))
            return qpr::runService();
        if (arg == QLatin1String("--install-service"))
            return qpr::installServiceCommand();
        if (arg == QLatin1String("--uninstall-service"))
            return qpr::uninstallServiceCommand();
    }
    qpr::startProxyService(nullptr);
    QApplication app(argc, argv);
    QApplication::setOrganizationName(QStringLiteral("stopRKN"));
    QApplication::setApplicationName(QStringLiteral("stopRKN"));
    QApplication::setApplicationVersion(QStringLiteral("0.9.0"));
    QNetworkProxy::setApplicationProxy(QNetworkProxy::NoProxy);
    QNetworkProxyFactory::setUseSystemConfiguration(false);
    qpr::CrashLog::installQt();
    qpr::CrashLog::write(QStringLiteral("ОКНО"), QString::fromUtf8("открыто"));
    app.setStyle(QStringLiteral("Fusion"));
    app.setWindowIcon(QIcon(QStringLiteral(":/shield.ico")));
    qpr::MainWindow window;
    window.show();
    return app.exec();
}
