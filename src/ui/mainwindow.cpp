#include "mainwindow.h"

#include "configstore.h"
#include "dialogs.h"
#include "hub.h"
#include "logger.h"
#include "platform.h"

#include <functional>

#include <QAbstractNativeEventFilter>
#include <QAbstractTableModel>
#include <QFile>
#include <QAction>
#include <QApplication>
#include <QCloseEvent>
#include <QCoreApplication>
#include <QDir>
#include <QComboBox>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QPainter>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QShortcut>
#include <QStatusBar>
#include <QTextBrowser>
#include <QSystemTrayIcon>
#include <QTabWidget>
#include <QTableView>
#include <QTimer>
#include <QToolBar>
#include <QVBoxLayout>

#ifdef Q_OS_WIN
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  include <shellapi.h>
#endif

namespace qpr {
namespace {

QString formatBytes(quint64 value)
{
    if (value < 1024)
        return QString::fromUtf8("%1 Б").arg(value);
    if (value < 1024 * 1024)
        return QString::fromUtf8("%1 КБ").arg(QString::number(value / 1024.0, 'f', 1));
    return QString::fromUtf8("%1 МБ").arg(QString::number(value / 1024.0 / 1024.0, 'f', 1));
}

QString levelName(LogLevel level)
{
    switch (level) {
    case LogLevel::Warning: return QStringLiteral("WARN");
    case LogLevel::Error: return QStringLiteral("ERROR");
    case LogLevel::Info: break;
    }
    return QStringLiteral("INFO");
}

class FlowModel : public QAbstractTableModel {
public:
    explicit FlowModel(QObject *parent = nullptr) : QAbstractTableModel(parent) {}
    int rowCount(const QModelIndex &parent = {}) const override { return parent.isValid() ? 0 : rows_.size(); }
    int columnCount(const QModelIndex &parent = {}) const override { return parent.isValid() ? 0 : 10; }
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override
    {
        if (orientation != Qt::Horizontal || role != Qt::DisplayRole)
            return {};
        static const char *headers[] = {"Время", "Процесс", "PID", "Источник", "Назначение",
                                        "Статус", "Через", "Отправлено", "Получено", "Правило"};
        return QString::fromUtf8(headers[section]);
    }
    QVariant data(const QModelIndex &index, int role) const override
    {
        if (!index.isValid() || index.row() >= rows_.size())
            return {};
        const FlowSnapshot &row = rows_.at(index.row());
        if (role == Qt::UserRole)
            return row.id;
        if (role == Qt::UserRole + 1)
            return row.pid;
        if (role != Qt::DisplayRole)
            return {};
        switch (index.column()) {
        case 0: return row.started.toString(QStringLiteral("HH:mm:ss"));
        case 1: return row.process;
        case 2: return row.pid ? QVariant(row.pid) : QVariant(QStringLiteral("—"));
        case 3: return row.source;
        case 4: return row.destination;
        case 5: return row.error.isEmpty() ? row.status : row.status + QStringLiteral(": ") + row.error;
        case 6: return row.via;
        case 7: return formatBytes(row.sent);
        case 8: return formatBytes(row.received);
        case 9: return row.rule;
        }
        return {};
    }
    void setRows(const QList<FlowSnapshot> &rows)
    {
        if (rows.size() != rows_.size()) {
            beginResetModel();
            rows_ = rows;
            endResetModel();
            return;
        }
        for (int i = 0; i < rows.size(); ++i) {
            if (rows.at(i).id != rows_.at(i).id) {
                beginResetModel();
                rows_ = rows;
                endResetModel();
                return;
            }
        }
        rows_ = rows;
        if (!rows_.isEmpty())
            emit dataChanged(index(0, 0), index(rows_.size() - 1, columnCount() - 1));
    }
    QList<FlowSnapshot> rows_;
};

QIcon shieldIcon()
{
    static const QIcon icon(QStringLiteral(":/shield.ico"));
    return icon;
}

class ProxyModel : public QAbstractTableModel {
public:
    explicit ProxyModel(QObject *parent = nullptr) : QAbstractTableModel(parent) {}
    int rowCount(const QModelIndex &parent = {}) const override { return parent.isValid() ? 0 : rows_.size(); }
    int columnCount(const QModelIndex &parent = {}) const override { return parent.isValid() ? 0 : 5; }
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override
    {
        if (orientation != Qt::Horizontal || role != Qt::DisplayRole)
            return {};
        static const char *headers[] = {"Имя", "Тип", "Адрес", "Щит", "Прикрытие"};
        return QString::fromUtf8(headers[section]);
    }
    QVariant data(const QModelIndex &index, int role) const override
    {
        if (!index.isValid() || index.row() >= rows_.size())
            return {};
        const Proxy &row = rows_.at(index.row());
        if (role == Qt::UserRole)
            return row.id;
        if (role == Qt::DecorationRole && index.column() == 3 && transportIsShield(row))
            return shieldIcon();
        if (role != Qt::DisplayRole)
            return {};
        switch (index.column()) {
        case 0: return row.name;
        case 1: return proxyTypeLabel(row.type);
        case 2: return QStringLiteral("%1:%2").arg(row.host).arg(row.port);
        case 3: return transportIsShield(row) ? QString::fromUtf8("да") : QString::fromUtf8("нет");
        case 4: return transportIsShield(row) ? coverOrDefault(row) : QString();
        }
        return {};
    }
    void setRows(QList<Proxy> rows)
    {
        beginResetModel();
        rows_ = std::move(rows);
        endResetModel();
    }
    QList<Proxy> rows_;
};

class ChainModel : public QAbstractTableModel {
public:
    QList<Chain> rows;
    QList<Proxy> proxies;
    int rowCount(const QModelIndex &parent = {}) const override { return parent.isValid() ? 0 : rows.size(); }
    int columnCount(const QModelIndex &parent = {}) const override { return parent.isValid() ? 0 : 2; }
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override
    {
        if (orientation != Qt::Horizontal || role != Qt::DisplayRole)
            return {};
        return section == 0 ? QString::fromUtf8("Цепочка") : QString::fromUtf8("Состав");
    }
    QVariant data(const QModelIndex &index, int role) const override
    {
        if (!index.isValid() || index.row() >= rows.size())
            return {};
        const Chain &row = rows.at(index.row());
        if (role == Qt::UserRole)
            return row.id;
        if (role != Qt::DisplayRole)
            return {};
        if (index.column() == 0)
            return row.name;
        QStringList names;
        for (const QString &id : row.proxyIds) {
            for (const Proxy &proxy : proxies) {
                if (proxy.id == id)
                    names.append(proxy.name);
            }
        }
        return names.join(QString::fromUtf8(" → "));
    }
    void reset()
    {
        beginResetModel();
        endResetModel();
    }
};

class SocialModel : public QAbstractTableModel {
public:
    QList<Rule> rows;
    AppConfig config;
    std::function<void(int, bool)> toggle;

    int rowCount(const QModelIndex &parent = {}) const override { return parent.isValid() ? 0 : rows.size(); }
    int columnCount(const QModelIndex &parent = {}) const override { return parent.isValid() ? 0 : 3; }
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override
    {
        if (orientation != Qt::Horizontal || role != Qt::DisplayRole)
            return {};
        static const char *headers[] = {"Активно", "Сервис", "Прокси"};
        return QString::fromUtf8(headers[section]);
    }
    Qt::ItemFlags flags(const QModelIndex &index) const override
    {
        if (!index.isValid())
            return Qt::NoItemFlags;
        Qt::ItemFlags bits = Qt::ItemIsEnabled | Qt::ItemIsSelectable;
        if (index.column() == 0)
            bits |= Qt::ItemIsUserCheckable;
        return bits;
    }
    QVariant data(const QModelIndex &index, int role) const override
    {
        if (!index.isValid() || index.row() >= rows.size())
            return {};
        const Rule &row = rows.at(index.row());
        if (role == Qt::UserRole)
            return row.id;
        if (role == Qt::CheckStateRole && index.column() == 0)
            return row.enabled ? Qt::Checked : Qt::Unchecked;
        if (role == Qt::TextAlignmentRole && index.column() == 0)
            return int(Qt::AlignCenter);
        if (role != Qt::DisplayRole || index.column() == 0)
            return {};
        if (index.column() == 1)
            return row.comment;
        for (const Proxy &proxy : config.proxies) {
            if (proxy.id == row.proxyId)
                return proxy.name;
        }
        return QString::fromUtf8("не выбран");
    }
    bool setData(const QModelIndex &index, const QVariant &value, int role) override
    {
        if (!index.isValid() || role != Qt::CheckStateRole || index.column() != 0 || !toggle)
            return false;
        const bool on = value.toInt() == Qt::Checked;
        if (on == rows.at(index.row()).enabled)
            return false;
        const int row = index.row();
        QTimer::singleShot(0, this, [this, row, on] {
            if (toggle)
                toggle(row, on);
        });
        return true;
    }
    void reset()
    {
        beginResetModel();
        endResetModel();
    }
};

class RuleModel : public QAbstractTableModel {
public:
    QList<Rule> rows;
    AppConfig config;
    int rowCount(const QModelIndex &parent = {}) const override { return parent.isValid() ? 0 : rows.size(); }
    int columnCount(const QModelIndex &parent = {}) const override { return parent.isValid() ? 0 : 6; }
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override
    {
        if (orientation != Qt::Horizontal || role != Qt::DisplayRole)
            return {};
        static const char *headers[] = {"Вкл", "Процесс", "Назначение", "Порты", "Действие", "Комментарий"};
        return QString::fromUtf8(headers[section]);
    }
    QVariant data(const QModelIndex &index, int role) const override
    {
        if (!index.isValid() || index.row() >= rows.size())
            return {};
        const Rule &row = rows.at(index.row());
        if (role == Qt::UserRole)
            return row.id;
        if (role != Qt::DisplayRole)
            return {};
        switch (index.column()) {
        case 0: return row.enabled ? QString::fromUtf8("да") : QString::fromUtf8("нет");
        case 1: return row.process.isEmpty() ? QStringLiteral("*") : row.process;
        case 2: return row.target.isEmpty() ? QStringLiteral("*") : row.target;
        case 3: return row.ports.isEmpty() ? QStringLiteral("*") : row.ports;
        case 4: {
            if (row.action == RuleAction::Block)
                return QString::fromUtf8("блок");
            if (row.action == RuleAction::Direct)
                return QString::fromUtf8("напрямую");
            if (row.action == RuleAction::Proxy) {
                for (const Proxy &proxy : config.proxies)
                    if (proxy.id == row.proxyId)
                        return proxy.name;
            }
            if (row.action == RuleAction::Chain) {
                for (const Chain &chain : config.chains)
                    if (chain.id == row.chainId)
                        return chain.name;
            }
            return QString::fromUtf8("прокси");
        }
        case 5: return row.comment;
        }
        return {};
    }
    void reset()
    {
        beginResetModel();
        endResetModel();
    }
};

class HotkeyFilter : public QAbstractNativeEventFilter {
public:
    std::function<void()> callback;
    bool nativeEventFilter(const QByteArray &, void *message, qintptr *) override
    {
#ifdef Q_OS_WIN
        auto *msg = static_cast<MSG *>(message);
        if (msg && msg->message == WM_HOTKEY && msg->wParam == 1) {
            if (callback)
                callback();
            return true;
        }
#else
        Q_UNUSED(message);
#endif
        return false;
    }
};

#ifdef Q_OS_WIN
bool splitHotkey(const QString &text, UINT *mods, UINT *vk)
{
    const QKeySequence sequence(text);
    if (sequence.isEmpty())
        return false;
    const QKeyCombination combo = sequence[0];
    UINT value = MOD_NOREPEAT;
    const Qt::KeyboardModifiers modifiers = combo.keyboardModifiers();
    if (modifiers.testFlag(Qt::ControlModifier))
        value |= MOD_CONTROL;
    if (modifiers.testFlag(Qt::ShiftModifier))
        value |= MOD_SHIFT;
    if (modifiers.testFlag(Qt::AltModifier))
        value |= MOD_ALT;
    if (modifiers.testFlag(Qt::MetaModifier))
        value |= MOD_WIN;
    const int key = int(combo.key());
    UINT code = 0;
    if (key >= Qt::Key_A && key <= Qt::Key_Z)
        code = UINT('A' + key - Qt::Key_A);
    else if (key >= Qt::Key_0 && key <= Qt::Key_9)
        code = UINT('0' + key - Qt::Key_0);
    else if (key >= Qt::Key_F1 && key <= Qt::Key_F24)
        code = VK_F1 + UINT(key - Qt::Key_F1);
    if (!code)
        return false;
    *mods = value;
    *vk = code;
    return true;
}
#endif

QWidget *page(QWidget *body, QWidget *buttons)
{
    auto *wrap = new QWidget;
    auto *layout = new QVBoxLayout(wrap);
    layout->setContentsMargins(8, 8, 8, 8);
    layout->addWidget(body);
    if (buttons)
        layout->addWidget(buttons);
    return wrap;
}

QPushButton *button(const QString &text, QWidget *parent)
{
    return new QPushButton(text, parent);
}

QString helpHtml()
{
    return QString::fromUtf8(
        "<h2>Как этим пользоваться</h2>"
        "<p>Программа пускает выбранные сайты и программы через другой компьютер — его называют прокси. "
        "Всё, для чего правила нет, открывается как обычно.</p>"
        "<h2>С чего начать</h2>"
        "<ol>"
        "<li>Откройте программу. Если наверху есть кнопка «Установить службу» — нажмите её и согласитесь с вопросом Windows. "
        "Кнопка сменится на «Служба работает». Без службы программы не перехватываются.</li>"
        "<li>Вкладка «Прокси», кнопка «Добавить». Впишите то, что вам выдали: адрес, порт, логин и пароль. "
        "Тип выберите тот, который назвали, чаще всего HTTP или SOCKS5. Имя может быть любым, например «Мой прокси». "
        "Нажмите «Сохранить», затем «Проверить». Должно появиться сообщение, что соединение есть.</li>"
        "<li>Вкладка «Правила». Соцсети уже в списке. Поставьте галку «Активно». Если прокси ещё не выбран, откроется окно, где его нужно указать.</li>"
        "<li>Наверху нажмите «Включить маршрутизацию». Внизу окна появится «маршрутизация включена».</li>"
        "<li>Сайт откройте заново. Старую вкладку браузера лучше закрыть и открыть снова.</li>"
        "</ol>"
        "<h2>Вкладки</h2>"
        "<p><b>Соединения.</b> Какая программа куда пошла: через прокси, напрямую или её не пустили. Список обновляется сам.</p>"
        "<p><b>Правила.</b> Сверху соцсети: галка включает сервис, двойной щелчок меняет прокси. "
        "Ниже свои правила. Список читается сверху вниз, выполняется первое подходящее. «Выше» и «Ниже» двигают свою строку. "
        "«Добавить» делает своё правило.</p>"
        "<ul>"
        "<li>Процесс — имя файла программы, например chrome.exe. Звёздочка * значит «любая программа».</li>"
        "<li>Назначение — сайт. Пустое поле тоже значит «любой».</li>"
        "<li>Через прокси — отправить на выбранный сервер.</li>"
        "<li>Напрямую — не трогать.</li>"
        "<li>Заблокировать — не пускать.</li>"
        "</ul>"
        "<p><b>Прокси.</b> Ваши серверы. «Проверить» делает пробное соединение. "
        "Цепочка нужна, только если вам сказали пускать через несколько серверов по очереди. Для одного сервера её не создавайте.</p>"
        "<p><b>Журнал.</b> Короткие сообщения о работе. Красная строка — ошибка. Если сайт не открылся, сначала смотрите сюда.</p>"
        "<h2>Две галочки в настройках</h2>"
        "<p><b>Ставить системный прокси Windows.</b> Включите, чтобы обычный браузер передавал названия сайтов. "
        "Тогда правила соцсетей срабатывают по имени. После галочки закройте браузер полностью и откройте снова. "
        "Если галочка снята, браузер может ходить сам, и программа видит только числовой адрес, без названия сайта. "
        "Сети YouTube, Instagram и Telegram при этом всё равно узнаются по адресу.</p>"
        "<p><b>Автозапуск с Windows</b> открывает окно при включении компьютера. Служба запускается сама и без этой галочки.</p>"
        "<p>Горячая клавиша прячет и показывает окно.</p>"
        "<h2>Щит</h2>"
        "<p>Включайте щит, только если вам отдельно выдали ключ и сказали, что он нужен. "
        "Это маскировка дороги до вашего сервера, а не другой адрес. Ключ пишется в карточке прокси. "
        "Обычному прокси щит не нужен: с ним сайты перестанут открываться.</p>"
        "<p>Пункт «Принимать входящие соединения щита» — для случая, когда к этому компьютеру подключаются другие. Дома его не включайте.</p>"
        "<h2>Если не работает</h2>"
        "<ul>"
        "<li>Внизу нет слова «служба» — нажмите «Установить службу».</li>"
        "<li>Написано «маршрутизация выключена» — нажмите «Включить маршрутизацию».</li>"
        "<li>«Проверить» пишет ошибку — неверны адрес, порт, логин или пароль, либо сервер недоступен.</li>"
        "<li>В журнале 502 или «таймаут» — программа до сервера дошла, а сам сервер не открыл сайт.</li>"
        "<li>Сайт из списка всё равно идёт напрямую — включите галку у этой соцсети и системный прокси, затем перезапустите браузер.</li>"
        "<li>Окно закрылось, а интернет всё ещё идёт через программу. Она спряталась у часов, справа внизу. "
        "Правый щелчок по значку и «Выход» выключают её совсем.</li>"
        "</ul>");
}

} // namespace

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    setWindowTitle(QStringLiteral("stopRKN"));
    resize(1180, 720);
    buildUi();
    engine_.load();
    if (ConfigStore::needsMachinePromotion(ConfigStore::defaultPath()))
        engine_.setConfig(engine_.config());
    hub_ = new HubClient(this);
    connect(hub_, &HubClient::statusReceived, this,
            [this](bool listening, quint16 socks, quint16 http, quint16 shield, bool divert, quint16 divertPort) {
                engine_.applyRemoteStatus(listening, socks, http, shield, divert, divertPort);
                updateTray();
            });
    connect(hub_, &HubClient::flowsReceived, this, [this](const QList<FlowSnapshot> &rows) {
        engine_.applyRemoteFlows(rows);
    });
    connect(hub_, &HubClient::logReceived, this, &MainWindow::appendLog);
    connect(hub_, &HubClient::disconnected, this, [this] {
        if (!engine_.delegated())
            return;
        engine_.setDelegated(false);
        engine_.start();
        if (serviceAction_) {
            serviceAction_->setEnabled(true);
            serviceAction_->setText(QString::fromUtf8("Установить службу"));
        }
        Logger::instance()->error(QString::fromUtf8(
            "Служба остановилась. Прокси для браузера работает из окна, перехват программ недоступен."));
        updateTray();
    });
    attachService();
    bindEngine();
    engine_.start();
    registerHotkey();
    updateTray();
}

MainWindow::~MainWindow()
{
#ifdef Q_OS_WIN
    UnregisterHotKey(reinterpret_cast<HWND>(winId()), 1);
#endif
    if (hotkeys_)
        qApp->removeNativeEventFilter(hotkeys_);
    delete hotkeys_;
    engine_.stop();
}

void MainWindow::buildUi()
{
    routingAction_ = new QAction(QString::fromUtf8("Включить маршрутизацию"), this);
    routingAction_->setCheckable(true);
    connect(routingAction_, &QAction::triggered, this, &MainWindow::toggleRouting);
    auto *clearLog = new QAction(QString::fromUtf8("Очистить журнал"), this);
    auto *settings = new QAction(QString::fromUtf8("Настройки"), this);
    serviceAction_ = new QAction(QString::fromUtf8("Установить службу"), this);
    auto *bar = addToolBar(QString::fromUtf8("Главная"));
    bar->setMovable(false);
    bar->addAction(routingAction_);
    bar->addAction(serviceAction_);
    bar->addAction(clearLog);
    bar->addAction(settings);
    auto *helpAction = new QAction(QString::fromUtf8("Справка"), this);
    bar->addAction(helpAction);
    connect(helpAction, &QAction::triggered, this, [this] {
        if (!tabs_)
            return;
        for (int i = 0; i < tabs_->count(); ++i) {
            if (tabs_->tabText(i) == QString::fromUtf8("Справка")) {
                tabs_->setCurrentIndex(i);
                break;
            }
        }
    });
    connect(serviceAction_, &QAction::triggered, this, &MainWindow::installService);
    connect(clearLog, &QAction::triggered, this, [this] {
        logView_->clear();
    });
    connect(settings, &QAction::triggered, this, [this] {
        AppConfig config = engine_.config();
        if (!editSettings(this, config))
            return;
        engine_.setConfig(config);
        syncService();
        registerHotkey();
        updateTray();
    });

    flowModel_ = new FlowModel(this);
    flowsView_ = new QTableView;
    flowsView_->setModel(flowModel_);
    flowsView_->setSelectionBehavior(QAbstractItemView::SelectRows);
    flowsView_->setSelectionMode(QAbstractItemView::SingleSelection);
    flowsView_->horizontalHeader()->setStretchLastSection(true);
    flowsView_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    flowsView_->verticalHeader()->setSectionResizeMode(QHeaderView::Fixed);
    flowsView_->verticalHeader()->setDefaultSectionSize(24);
    flowsView_->verticalHeader()->setVisible(false);
    auto *closeFlow = button(QString::fromUtf8("Закрыть соединение"), this);
    auto *closePid = button(QString::fromUtf8("Закрыть процесс"), this);
    auto *clearClosed = button(QString::fromUtf8("Убрать закрытые"), this);
    auto *flowButtons = new QWidget;
    auto *flowRow = new QHBoxLayout(flowButtons);
    flowRow->addWidget(closeFlow);
    flowRow->addWidget(closePid);
    flowRow->addWidget(clearClosed);
    flowRow->addStretch();
    connect(closeFlow, &QPushButton::clicked, this, [this] {
        const auto index = flowsView_->currentIndex();
        if (!index.isValid())
            return;
        const QString id = index.data(Qt::UserRole).toString();
        if (engine_.delegated())
            hub_->closeFlow(id);
        else
            engine_.closeFlow(id);
    });
    connect(closePid, &QPushButton::clicked, this, [this] {
        const auto index = flowsView_->currentIndex();
        if (!index.isValid())
            return;
        const quint32 pid = index.data(Qt::UserRole + 1).toUInt();
        if (engine_.delegated())
            hub_->closePid(pid);
        else
            engine_.closePid(pid);
    });
    connect(clearClosed, &QPushButton::clicked, this, [this] {
        if (engine_.delegated())
            hub_->clearClosed();
        else
            engine_.clearClosed();
    });

    proxyModel_ = new ProxyModel(this);
    proxyView_ = new QTableView;
    proxyView_->setModel(proxyModel_);
    proxyView_->setSelectionBehavior(QAbstractItemView::SelectRows);
    proxyView_->setSelectionMode(QAbstractItemView::SingleSelection);
    proxyView_->horizontalHeader()->setStretchLastSection(true);
    proxyView_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    proxyView_->verticalHeader()->setVisible(false);
    chainModel_ = new ChainModel;
    chainModel_->setParent(this);
    chainView_ = new QTableView;
    chainView_->setModel(chainModel_);
    chainView_->setSelectionBehavior(QAbstractItemView::SelectRows);
    chainView_->horizontalHeader()->setStretchLastSection(true);
    chainView_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    chainView_->verticalHeader()->setVisible(false);
    chainView_->setMaximumHeight(180);
    auto *addProxy = button(QString::fromUtf8("Добавить прокси"), this);
    auto *editProxyButton = button(QString::fromUtf8("Изменить"), this);
    auto *removeProxy = button(QString::fromUtf8("Удалить"), this);
    auto *testProxy = button(QString::fromUtf8("Проверить"), this);
    auto *addChain = button(QString::fromUtf8("Добавить цепочку"), this);
    auto *editChainButton = button(QString::fromUtf8("Изменить цепочку"), this);
    auto *removeChain = button(QString::fromUtf8("Удалить цепочку"), this);
    auto *testChain = button(QString::fromUtf8("Проверить цепочку"), this);
    auto *proxyButtons = new QWidget;
    auto *proxyRow = new QHBoxLayout(proxyButtons);
    for (auto *item : {addProxy, editProxyButton, removeProxy, testProxy, addChain, editChainButton, removeChain, testChain})
        proxyRow->addWidget(item);
    proxyRow->addStretch();
    auto *proxyPage = new QWidget;
    auto *proxyLayout = new QVBoxLayout(proxyPage);
    proxyLayout->addWidget(proxyView_, 3);
    proxyLayout->addWidget(new QLabel(QString::fromUtf8(
        "Щит подменяет только «обложку» первого пакета. Пакеты идут на адрес вашего сервера.")));
    proxyLayout->addWidget(chainView_, 1);
    proxyLayout->addWidget(proxyButtons);

    auto mutate = [this](auto changer) {
        AppConfig config = engine_.config();
        if (!changer(config))
            return;
        engine_.setConfig(config);
        syncService();
        refreshProxies();
        refreshRules();
    };
    connect(addProxy, &QPushButton::clicked, this, [=] {
        mutate([](AppConfig &config) {
            Proxy proxy;
            proxy.port = 443;
            proxy.type = ProxyType::Shield;
            proxy.coverHost = QStringLiteral("ya.ru");
            if (!editProxy(nullptr, proxy))
                return false;
            config.proxies.append(proxy);
            return true;
        });
    });
    connect(editProxyButton, &QPushButton::clicked, this, [=] {
        const int row = proxyView_->currentIndex().row();
        if (row < 0)
            return;
        mutate([row](AppConfig &config) {
            if (row >= config.proxies.size())
                return false;
            return editProxy(nullptr, config.proxies[row]);
        });
    });
    connect(proxyView_, &QTableView::doubleClicked, editProxyButton, &QPushButton::click);
    connect(removeProxy, &QPushButton::clicked, this, [=] {
        const int row = proxyView_->currentIndex().row();
        if (row < 0)
            return;
        mutate([row](AppConfig &config) {
            if (row >= config.proxies.size())
                return false;
            const QString id = config.proxies.at(row).id;
            config.proxies.removeAt(row);
            for (Rule &rule : config.rules)
                if (rule.proxyId == id)
                    rule.proxyId.clear();
            for (Chain &chain : config.chains)
                chain.proxyIds.removeAll(id);
            return true;
        });
    });
    connect(testProxy, &QPushButton::clicked, this, [this] {
        const int row = proxyView_->currentIndex().row();
        if (row < 0 || row >= engine_.config().proxies.size())
            return;
        const Proxy proxy = engine_.config().proxies.at(row);
        engine_.testProxy(proxy, [this](const QString &message, bool ok) {
            QMessageBox box(this);
            box.setWindowTitle(QString::fromUtf8("Проверка прокси"));
            box.setText(message);
            box.setIcon(ok ? QMessageBox::Information : QMessageBox::Warning);
            box.exec();
        });
    });
    connect(addChain, &QPushButton::clicked, this, [=] {
        mutate([](AppConfig &config) {
            Chain chain;
            if (!editChain(nullptr, chain, config))
                return false;
            config.chains.append(chain);
            return true;
        });
    });
    connect(editChainButton, &QPushButton::clicked, this, [=] {
        const int row = chainView_->currentIndex().row();
        if (row < 0)
            return;
        mutate([row](AppConfig &config) {
            if (row >= config.chains.size())
                return false;
            return editChain(nullptr, config.chains[row], config);
        });
    });
    connect(removeChain, &QPushButton::clicked, this, [=] {
        const int row = chainView_->currentIndex().row();
        if (row < 0)
            return;
        mutate([row](AppConfig &config) {
            if (row >= config.chains.size())
                return false;
            config.chains.removeAt(row);
            return true;
        });
    });
    connect(testChain, &QPushButton::clicked, this, [this] {
        const int row = chainView_->currentIndex().row();
        if (row < 0 || row >= engine_.config().chains.size())
            return;
        engine_.testChain(engine_.config().chains.at(row), [this](const QString &message, bool ok) {
            QMessageBox::information(this, QString::fromUtf8("Проверка цепочки"), message);
            Q_UNUSED(ok);
        });
    });

    auto customPos = [](const AppConfig &config, int viewRow) {
        int seen = -1;
        for (int i = 0; i < config.rules.size(); ++i) {
            if (!config.rules.at(i).builtin.isEmpty())
                continue;
            ++seen;
            if (seen == viewRow)
                return i;
        }
        return -1;
    };
    auto proxyAssigned = [](const AppConfig &config, const QString &id) {
        if (id.isEmpty())
            return false;
        for (const Proxy &proxy : config.proxies) {
            if (proxy.id == id)
                return true;
        }
        return false;
    };
    socialModel_ = new SocialModel;
    socialModel_->setParent(this);
    socialView_ = new QTableView;
    socialView_->setModel(socialModel_);
    socialView_->setSelectionBehavior(QAbstractItemView::SelectRows);
    socialView_->setSelectionMode(QAbstractItemView::SingleSelection);
    socialView_->horizontalHeader()->setStretchLastSection(true);
    socialView_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    socialView_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    socialView_->verticalHeader()->setVisible(false);
    socialView_->setMinimumHeight(260);
    static_cast<SocialModel *>(socialModel_)->toggle = [this, proxyAssigned](int row, bool on) {
        const QList<Rule> shown = static_cast<SocialModel *>(socialModel_)->rows;
        if (row < 0 || row >= shown.size())
            return;
        const QString id = shown.at(row).id;
        AppConfig config = engine_.config();
        bool changed = false;
        for (Rule &rule : config.rules) {
            if (rule.id != id)
                continue;
            if (!on) {
                rule.enabled = false;
                changed = true;
                break;
            }
            if (!proxyAssigned(config, rule.proxyId)) {
                QString proxyId;
                if (!pickProxy(this, config, rule.comment, &proxyId)) {
                    refreshRules();
                    return;
                }
                rule.proxyId = proxyId;
                rule.action = RuleAction::Proxy;
            }
            rule.enabled = true;
            changed = true;
            break;
        }
        if (!changed)
            return;
        engine_.setConfig(config);
        syncService();
        refreshRules();
    };
    connect(socialView_, &QTableView::doubleClicked, this, [this](const QModelIndex &index) {
        if (!index.isValid() || index.column() == 0)
            return;
        const QString id = index.data(Qt::UserRole).toString();
        AppConfig config = engine_.config();
        for (Rule &rule : config.rules) {
            if (rule.id != id || rule.builtin.isEmpty())
                continue;
            QString proxyId = rule.proxyId;
            if (!pickProxy(this, config, rule.comment, &proxyId))
                return;
            rule.proxyId = proxyId;
            rule.action = RuleAction::Proxy;
            engine_.setConfig(config);
            syncService();
            refreshRules();
            return;
        }
    });
    ruleModel_ = new RuleModel;
    ruleModel_->setParent(this);
    rulesView_ = new QTableView;
    rulesView_->setModel(ruleModel_);
    rulesView_->setSelectionBehavior(QAbstractItemView::SelectRows);
    rulesView_->horizontalHeader()->setStretchLastSection(true);
    rulesView_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    rulesView_->verticalHeader()->setVisible(false);
    auto *addRule = button(QString::fromUtf8("Добавить"), this);
    auto *editRuleButton = button(QString::fromUtf8("Изменить"), this);
    auto *removeRule = button(QString::fromUtf8("Удалить"), this);
    auto *upRule = button(QString::fromUtf8("Выше"), this);
    auto *downRule = button(QString::fromUtf8("Ниже"), this);
    auto *ruleButtons = new QWidget;
    auto *ruleRow = new QHBoxLayout(ruleButtons);
    for (auto *item : {addRule, editRuleButton, removeRule, upRule, downRule})
        ruleRow->addWidget(item);
    ruleRow->addStretch();
    auto *ruleHint = new QLabel(QString::fromUtf8(
        "Галка включает соцсеть. Если прокси ещё не выбран, откроется окно выбора. "
        "Двойной щелчок по строке меняет прокси. Свои правила ниже проверяются после соцсетей."));
    ruleHint->setWordWrap(true);
    connect(addRule, &QPushButton::clicked, this, [=] {
        mutate([](AppConfig &config) {
            Rule rule;
            rule.process = QStringLiteral("*");
            if (!editRule(nullptr, rule, config))
                return false;
            config.rules.append(rule);
            return true;
        });
    });
    connect(editRuleButton, &QPushButton::clicked, this, [=, customPos] {
        const int row = rulesView_->currentIndex().row();
        if (row < 0)
            return;
        mutate([row, customPos](AppConfig &config) {
            const int pos = customPos(config, row);
            if (pos < 0)
                return false;
            return editRule(nullptr, config.rules[pos], config);
        });
    });
    connect(rulesView_, &QTableView::doubleClicked, editRuleButton, &QPushButton::click);
    connect(removeRule, &QPushButton::clicked, this, [=, customPos] {
        const int row = rulesView_->currentIndex().row();
        if (row < 0)
            return;
        mutate([row, customPos](AppConfig &config) {
            const int pos = customPos(config, row);
            if (pos < 0)
                return false;
            config.rules.removeAt(pos);
            return true;
        });
    });
    auto moveRule = [this, customPos](int delta) {
        const int row = rulesView_->currentIndex().row();
        if (row < 0)
            return;
        AppConfig config = engine_.config();
        const int from = customPos(config, row);
        const int to = customPos(config, row + delta);
        if (from < 0 || to < 0)
            return;
        config.rules.swapItemsAt(from, to);
        engine_.setConfig(config);
        syncService();
        refreshRules();
        rulesView_->selectRow(row + delta);
    };
    connect(upRule, &QPushButton::clicked, this, [=] { moveRule(-1); });
    connect(downRule, &QPushButton::clicked, this, [=] { moveRule(1); });
    auto *rulesPage = new QWidget;
    auto *rulesLayout = new QVBoxLayout(rulesPage);
    rulesLayout->addWidget(ruleHint);
    rulesLayout->addWidget(socialView_, 2);
    auto *customLabel = new QLabel(QString::fromUtf8("Свои правила"));
    rulesLayout->addWidget(customLabel);
    rulesLayout->addWidget(rulesView_, 1);
    rulesLayout->addWidget(ruleButtons);

    logView_ = new QPlainTextEdit;
    logView_->setReadOnly(true);
    logView_->setMaximumBlockCount(5000);
    auto *filter = new QComboBox;
    filter->addItems({QString::fromUtf8("Все"), QStringLiteral("Info"), QStringLiteral("Warning"), QStringLiteral("Error")});
    auto *search = new QLineEdit;
    search->setPlaceholderText(QString::fromUtf8("поиск"));
    auto *saveLog = button(QString::fromUtf8("Сохранить в файл"), this);
    auto *logButtons = new QWidget;
    auto *logRow = new QHBoxLayout(logButtons);
    logRow->addWidget(filter);
    logRow->addWidget(search, 1);
    logRow->addWidget(saveLog);
    connect(filter, &QComboBox::currentIndexChanged, this, [this](int index) {
        logFilter_ = index;
        logView_->clear();
        for (const Logger::Line &line : Logger::instance()->history())
            appendLog(line.level, line.time, line.text);
    });
    connect(search, &QLineEdit::textChanged, this, [this](const QString &text) {
        logSearch_ = text;
        logView_->clear();
        for (const Logger::Line &line : Logger::instance()->history())
            appendLog(line.level, line.time, line.text);
    });
    connect(saveLog, &QPushButton::clicked, this, [this] {
        const QString path = QFileDialog::getSaveFileName(this, QString::fromUtf8("Сохранить журнал"),
                                                          QStringLiteral("stopRKN.log"),
                                                          QString::fromUtf8("Текст (*.log *.txt)"));
        if (path.isEmpty())
            return;
        QFile file(path);
        if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate))
            return;
        file.write(logView_->toPlainText().toUtf8());
    });

    tabs_ = new QTabWidget;
    tabs_->addTab(page(flowsView_, flowButtons), QString::fromUtf8("Соединения"));
    tabs_->addTab(rulesPage, QString::fromUtf8("Правила"));
    tabs_->addTab(proxyPage, QString::fromUtf8("Прокси"));
    tabs_->addTab(page(logView_, logButtons), QString::fromUtf8("Журнал"));
    auto *help = new QTextBrowser;
    help->setOpenExternalLinks(false);
    help->setStyleSheet(QStringLiteral("QTextBrowser { font-size: 15px; }"));
    help->setHtml(helpHtml());
    tabs_->addTab(page(help, nullptr), QString::fromUtf8("Справка"));
    connect(tabs_, &QTabWidget::currentChanged, this, [this](int index) {
        if (index == 0)
            refreshFlows();
    });
    setCentralWidget(tabs_);
    status_ = new QLabel;
    statusBar()->addWidget(status_, 1);

    tray_ = new QSystemTrayIcon(this);
    auto *menu = new QMenu(this);
    auto *show = menu->addAction(QString::fromUtf8("Открыть"));
    menu->addAction(routingAction_);
    menu->addSeparator();
    auto *quit = menu->addAction(QString::fromUtf8("Выход"));
    tray_->setContextMenu(menu);
    connect(show, &QAction::triggered, this, [this] { showNormal(); activateWindow(); });
    connect(tray_, &QSystemTrayIcon::activated, this, [this](QSystemTrayIcon::ActivationReason reason) {
        if (reason == QSystemTrayIcon::Trigger || reason == QSystemTrayIcon::DoubleClick) {
            showNormal();
            activateWindow();
        }
    });
    connect(quit, &QAction::triggered, this, [this] {
        quit_ = true;
        close();
    });
    tray_->show();

    auto *timer = new QTimer(this);
    connect(timer, &QTimer::timeout, this, &MainWindow::refreshFlows);
    timer->start(500);
    connect(Logger::instance(), &Logger::logged, this, &MainWindow::appendLog);
    for (const Logger::Line &line : Logger::instance()->history())
        appendLog(line.level, line.time, line.text);
}

void MainWindow::bindEngine()
{
    connect(&engine_, &Engine::routingChanged, this, [this](bool enabled) {
        routingAction_->setChecked(enabled);
        routingAction_->setText(enabled ? QString::fromUtf8("Выключить маршрутизацию")
                                        : QString::fromUtf8("Включить маршрутизацию"));
        updateTray();
    });
    connect(&engine_, &Engine::listeningChanged, this, [this] { updateTray(); });
    refreshProxies();
    refreshRules();
    routingAction_->setChecked(engine_.config().routingEnabled);
}

void MainWindow::refreshFlows()
{
    const bool connectionsVisible = tabs_ && tabs_->currentWidget() && tabs_->currentIndex() == 0;
    if (connectionsVisible)
        static_cast<FlowModel *>(flowModel_)->setRows(engine_.snapshots());
    const int active = engine_.flowCount();
    QStringList parts;
    if (engine_.socksPort())
        parts.append(QStringLiteral("SOCKS %1:%2").arg(engine_.config().listenHost).arg(engine_.socksPort()));
    if (engine_.httpPort())
        parts.append(QStringLiteral("HTTP %1:%2").arg(engine_.config().listenHost).arg(engine_.httpPort()));
    if (engine_.shieldPort())
        parts.append(QString::fromUtf8("щит %1:%2").arg(engine_.config().shieldListenHost).arg(engine_.shieldPort()));
    parts.append(engine_.config().routingEnabled ? QString::fromUtf8("маршрутизация включена")
                                                 : QString::fromUtf8("маршрутизация выключена"));
    parts.append(engine_.delegated() ? QString::fromUtf8("служба") : QString::fromUtf8("без службы"));
    if (engine_.config().routingEnabled) {
        parts.append(engine_.divertActive()
                         ? QString::fromUtf8("перехват TCP %1").arg(engine_.divertPort())
                         : QString::fromUtf8("перехват TCP не запущен"));
    }
    parts.append(QString::fromUtf8("записей: %1").arg(active));
    status_->setText(parts.join(QStringLiteral("  |  ")));
}

void MainWindow::refreshProxies()
{
    static_cast<ProxyModel *>(proxyModel_)->setRows(engine_.config().proxies);
    auto *chains = static_cast<ChainModel *>(chainModel_);
    chains->proxies = engine_.config().proxies;
    chains->rows = engine_.config().chains;
    chains->reset();
}

void MainWindow::refreshRules()
{
    QList<Rule> social;
    QList<Rule> custom;
    for (const Rule &rule : engine_.config().rules) {
        if (rule.builtin.isEmpty())
            custom.append(rule);
        else
            social.append(rule);
    }
    auto *socialModel = static_cast<SocialModel *>(socialModel_);
    if (socialModel) {
        socialModel->config = engine_.config();
        socialModel->rows = social;
        socialModel->reset();
    }
    auto *rules = static_cast<RuleModel *>(ruleModel_);
    rules->config = engine_.config();
    rules->rows = custom;
    rules->reset();
}

void MainWindow::appendLog(LogLevel level, const QDateTime &time, const QString &text)
{
    if (!logView_)
        return;
    if (logFilter_ == 1 && level != LogLevel::Info)
        return;
    if (logFilter_ == 2 && level != LogLevel::Warning)
        return;
    if (logFilter_ == 3 && level != LogLevel::Error)
        return;
    if (!logSearch_.isEmpty() && !text.contains(logSearch_, Qt::CaseInsensitive))
        return;
    const QString line = QStringLiteral("%1  %2  %3")
                             .arg(time.toString(QStringLiteral("HH:mm:ss")), levelName(level), text);
    logView_->appendPlainText(line);
}

void MainWindow::toggleRouting()
{
    engine_.setRoutingEnabled(routingAction_->isChecked());
    syncService();
    updateTray();
}

void MainWindow::syncService()
{
    if (hub_ && hub_->active())
        hub_->reload();
}

void MainWindow::attachService()
{
    if (!hub_->waitForService(800)) {
        serviceAction_->setText(QString::fromUtf8("Установить службу"));
        Logger::instance()->info(QString::fromUtf8(
            "Служба не запущена, перехват без прав администратора недоступен. Нажмите «Установить службу»."));
        return;
    }
    engine_.releasePorts();
    engine_.setDelegated(true);
    serviceAction_->setText(QString::fromUtf8("Служба работает"));
    serviceAction_->setEnabled(false);
    Logger::instance()->info(QString::fromUtf8("Окно подключено к службе. Права администратора для интерфейса не нужны."));
}

void MainWindow::installService()
{
    if (engine_.delegated())
        return;
#ifdef Q_OS_WIN
    engine_.releasePorts();
    const QString exe = QDir::toNativeSeparators(QCoreApplication::applicationFilePath());
    SHELLEXECUTEINFOW info{};
    info.cbSize = sizeof(info);
    info.fMask = SEE_MASK_NOCLOSEPROCESS;
    info.lpVerb = L"runas";
    info.lpFile = reinterpret_cast<LPCWSTR>(exe.utf16());
    info.lpParameters = L"--install-service";
    info.nShow = SW_HIDE;
    if (!ShellExecuteExW(&info)) {
        Logger::instance()->error(QString::fromUtf8("Установка службы отменена"));
        engine_.start();
        return;
    }
    if (info.hProcess) {
        WaitForSingleObject(info.hProcess, 20000);
        CloseHandle(info.hProcess);
    }
    attachService();
    engine_.start();
    if (engine_.delegated())
        syncService();
#else
    Logger::instance()->error(QString::fromUtf8("Служба поддерживается только в Windows"));
#endif
}

void MainWindow::registerHotkey()
{
    const auto old = findChildren<QShortcut *>();
    for (QShortcut *shortcut : old)
        shortcut->deleteLater();
    auto *shortcut = new QShortcut(QKeySequence(engine_.config().hotkey), this);
    connect(shortcut, &QShortcut::activated, this, [this] {
        routingAction_->setChecked(!engine_.config().routingEnabled);
        toggleRouting();
    });
#ifdef Q_OS_WIN
    UnregisterHotKey(reinterpret_cast<HWND>(winId()), 1);
    UINT mods = 0;
    UINT vk = 0;
    if (!splitHotkey(engine_.config().hotkey, &mods, &vk))
        return;
    if (!RegisterHotKey(reinterpret_cast<HWND>(winId()), 1, mods, vk))
        Logger::instance()->warn(QString::fromUtf8("Не удалось занять горячую клавишу %1").arg(engine_.config().hotkey));
    if (!hotkeys_) {
        auto *filter = new HotkeyFilter;
        filter->callback = [this] {
            routingAction_->setChecked(!engine_.config().routingEnabled);
            toggleRouting();
        };
        hotkeys_ = filter;
        qApp->installNativeEventFilter(hotkeys_);
    }
#endif
}

void MainWindow::updateTray()
{
    const bool on = engine_.config().routingEnabled && engine_.listening();
    const QIcon icon = statusIcon(on);
    tray_->setIcon(icon);
    setWindowIcon(icon);
    tray_->setToolTip(on ? QString::fromUtf8("stopRKN: маршрутизация включена")
                         : QString::fromUtf8("stopRKN: маршрутизация выключена"));
}

QIcon MainWindow::statusIcon(bool active) const
{
    if (active)
        return shieldIcon();
    QIcon dim;
    for (int side : {16, 24, 32, 48}) {
        const QPixmap src = shieldIcon().pixmap(side, side);
        QPixmap out(src.size());
        out.fill(Qt::transparent);
        QPainter painter(&out);
        painter.setOpacity(0.45);
        painter.drawPixmap(0, 0, src);
        dim.addPixmap(out);
    }
    return dim;
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    if (!quit_) {
        event->ignore();
        hide();
        if (!trayHintShown_) {
            trayHintShown_ = true;
            tray_->showMessage(QStringLiteral("stopRKN"),
                               QString::fromUtf8("Окно спрятано в трей. Маршрутизация продолжает работать."));
        }
        return;
    }
    engine_.stop();
    QMainWindow::closeEvent(event);
}

} // namespace qpr
