#pragma once

#include "engine.h"

#include <QMainWindow>

class QAbstractNativeEventFilter;
class QAbstractTableModel;
class QAction;
class QLabel;
class QPlainTextEdit;
class QSystemTrayIcon;
class QTableView;
class QTabWidget;

namespace qpr {

class HubClient;

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override;

protected:
    void closeEvent(QCloseEvent *event) override;

private:
    void buildUi();
    void bindEngine();
    void refreshFlows();
    void refreshProxies();
    void refreshRules();
    void appendLog(LogLevel level, const QDateTime &time, const QString &text);
    void toggleRouting();
    void registerHotkey();
    void updateTray();
    void attachService();
    void syncService();
    void installService();
    QIcon statusIcon(bool active) const;

    Engine engine_;
    HubClient *hub_ = nullptr;
    QAction *serviceAction_ = nullptr;
    QTabWidget *tabs_ = nullptr;
    QTableView *flowsView_ = nullptr;
    QTableView *proxyView_ = nullptr;
    QTableView *chainView_ = nullptr;
    QTableView *socialView_ = nullptr;
    QTableView *rulesView_ = nullptr;
    QPlainTextEdit *logView_ = nullptr;
    QLabel *status_ = nullptr;
    QAction *routingAction_ = nullptr;
    QSystemTrayIcon *tray_ = nullptr;
    QAbstractNativeEventFilter *hotkeys_ = nullptr;
    QAbstractTableModel *flowModel_ = nullptr;
    QAbstractTableModel *proxyModel_ = nullptr;
    QAbstractTableModel *chainModel_ = nullptr;
    QAbstractTableModel *socialModel_ = nullptr;
    QAbstractTableModel *ruleModel_ = nullptr;
    bool quit_ = false;
    bool trayHintShown_ = false;
    bool serviceInstalled_ = false;
    bool serviceRunning_ = false;
    bool serviceAlertShown_ = false;
    int logFilter_ = 0;
    QString logSearch_;
};

} // namespace qpr
