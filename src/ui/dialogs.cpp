#include "dialogs.h"

#include "cidr.h"

#include <QCheckBox>
#include <QComboBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QIcon>
#include <QHBoxLayout>
#include <QKeySequenceEdit>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMessageBox>
#include <QPushButton>
#include <QSpinBox>
#include <QVBoxLayout>

namespace qpr {
namespace {

QDialogButtonBox *buttons(QDialog *dialog)
{
    auto *box = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, dialog);
    box->button(QDialogButtonBox::Ok)->setText(QString::fromUtf8("Сохранить"));
    box->button(QDialogButtonBox::Cancel)->setText(QString::fromUtf8("Отмена"));
    QObject::connect(box, &QDialogButtonBox::accepted, dialog, &QDialog::accept);
    QObject::connect(box, &QDialogButtonBox::rejected, dialog, &QDialog::reject);
    return box;
}

void warn(QWidget *parent, const QString &text)
{
    QMessageBox::warning(parent, QStringLiteral("stopRKN"), text);
}

} // namespace

bool editProxy(QWidget *parent, Proxy &proxy)
{
    QDialog dialog(parent);
    dialog.setWindowTitle(proxy.id.isEmpty() ? QString::fromUtf8("Новый прокси") : QString::fromUtf8("Прокси"));
    dialog.resize(460, 420);
    auto *name = new QLineEdit(proxy.name);
    auto *type = new QComboBox;
    const ProxyType types[] = {ProxyType::Socks5, ProxyType::Socks4, ProxyType::Socks4a,
                               ProxyType::Http, ProxyType::Https, ProxyType::Shield};
    for (ProxyType item : types)
        type->addItem(proxyTypeLabel(item), int(item));
    type->setCurrentIndex(type->findData(int(proxy.type)));
    auto *host = new QLineEdit(proxy.host);
    host->setPlaceholderText(QString::fromUtf8("адрес вашего сервера"));
    auto *port = new QSpinBox;
    port->setRange(1, 65535);
    port->setValue(proxy.port > 0 ? proxy.port : 1080);
    auto *user = new QLineEdit(proxy.user);
    auto *password = new QLineEdit(proxy.password);
    password->setEchoMode(QLineEdit::Password);
    auto *shield = new QCheckBox(QString::fromUtf8("Обернуть соединение в щит DPI"));
    shield->setIcon(QIcon(QStringLiteral(":/shield.ico")));
    shield->setIconSize(QSize(18, 18));
    shield->setChecked(proxy.shield || proxy.type == ProxyType::Shield);
    auto *cover = new QComboBox;
    cover->setEditable(true);
    const QStringList covers = {QStringLiteral("ya.ru"), QStringLiteral("yandex.ru"),
                                QStringLiteral("mail.yandex.ru"), QStringLiteral("vk.com"),
                                QStringLiteral("mail.ru")};
    cover->addItems(covers);
    cover->setCurrentText(proxy.coverHost.isEmpty() ? QStringLiteral("ya.ru") : proxy.coverHost);
    auto *psk = new QLineEdit(proxy.shieldPsk);
    psk->setEchoMode(QLineEdit::Password);
    psk->setPlaceholderText(QString::fromUtf8("если пусто — берётся пароль"));
    auto *insecure = new QCheckBox(QString::fromUtf8("Не проверять сертификат HTTPS-прокси"));
    insecure->setChecked(proxy.tlsInsecure);
    auto *hint = new QLabel(QString::fromUtf8(
        "Имя прикрытия попадает только в SNI ClientHello, чтобы DPI увидел знакомый домен. "
        "TCP-соединение идёт на адрес сервера выше. К серверам этого домена приложение не подключается."));
    hint->setWordWrap(true);
    auto *form = new QFormLayout;
    form->addRow(QString::fromUtf8("Имя"), name);
    form->addRow(QString::fromUtf8("Тип"), type);
    form->addRow(QString::fromUtf8("Адрес сервера"), host);
    form->addRow(QString::fromUtf8("Порт"), port);
    form->addRow(QString::fromUtf8("Логин"), user);
    form->addRow(QString::fromUtf8("Пароль"), password);
    form->addRow(QString(), shield);
    form->addRow(QString::fromUtf8("Имя прикрытия"), cover);
    form->addRow(QString::fromUtf8("Ключ щита"), psk);
    form->addRow(QString(), insecure);
    auto *layout = new QVBoxLayout(&dialog);
    layout->addLayout(form);
    layout->addWidget(hint);
    layout->addWidget(buttons(&dialog));
    auto sync = [=] {
        const auto kind = ProxyType(type->currentData().toInt());
        const bool exit = kind == ProxyType::Shield;
        shield->setEnabled(!exit && kind != ProxyType::Https);
        if (exit)
            shield->setChecked(true);
        if (kind == ProxyType::Https)
            shield->setChecked(false);
        insecure->setVisible(kind == ProxyType::Https);
    };
    QObject::connect(type, &QComboBox::currentIndexChanged, &dialog, sync);
    sync();
    if (dialog.exec() != QDialog::Accepted)
        return false;
    if (name->text().trimmed().isEmpty() || host->text().trimmed().isEmpty()) {
        warn(parent, QString::fromUtf8("Нужны имя и адрес сервера."));
        return false;
    }
    proxy.name = name->text().trimmed();
    proxy.type = ProxyType(type->currentData().toInt());
    proxy.host = host->text().trimmed();
    proxy.port = static_cast<quint16>(port->value());
    proxy.user = user->text();
    proxy.password = password->text();
    proxy.shield = shield->isChecked() && proxy.type != ProxyType::Https;
    proxy.coverHost = cover->currentText().trimmed();
    proxy.shieldPsk = psk->text();
    proxy.tlsInsecure = insecure->isChecked();
    if (proxy.id.isEmpty())
        proxy.id = newId();
    if (transportIsShield(proxy) && effectivePsk(proxy).isEmpty()) {
        warn(parent, QString::fromUtf8("Для щита укажите ключ или пароль. Его же нужно задать на сервере."));
        return false;
    }
    return true;
}

bool editRule(QWidget *parent, Rule &rule, const AppConfig &config)
{
    QDialog dialog(parent);
    dialog.setWindowTitle(QString::fromUtf8("Правило"));
    auto *enabled = new QCheckBox(QString::fromUtf8("Включено"));
    enabled->setChecked(rule.enabled);
    auto *process = new QLineEdit(rule.process);
    process->setPlaceholderText(QString::fromUtf8("firefox.exe или * — любое"));
    auto *target = new QLineEdit(rule.target);
    target->setPlaceholderText(QString::fromUtf8("10.0.0.0/8, *.local или пусто"));
    auto *ports = new QLineEdit(rule.ports);
    ports->setPlaceholderText(QString::fromUtf8("80,443,8000-8100"));
    auto *action = new QComboBox;
    action->addItem(QString::fromUtf8("Напрямую"), int(RuleAction::Direct));
    action->addItem(QString::fromUtf8("Заблокировать"), int(RuleAction::Block));
    action->addItem(QString::fromUtf8("Через прокси"), int(RuleAction::Proxy));
    action->addItem(QString::fromUtf8("Через цепочку"), int(RuleAction::Chain));
    action->setCurrentIndex(qMax(0, action->findData(int(rule.action))));
    auto *proxy = new QComboBox;
    for (const Proxy &item : config.proxies)
        proxy->addItem(item.name, item.id);
    proxy->setCurrentIndex(qMax(0, proxy->findData(rule.proxyId)));
    auto *chain = new QComboBox;
    for (const Chain &item : config.chains)
        chain->addItem(item.name, item.id);
    chain->setCurrentIndex(qMax(0, chain->findData(rule.chainId)));
    auto *comment = new QLineEdit(rule.comment);
    auto *form = new QFormLayout;
    form->addRow(QString(), enabled);
    form->addRow(QString::fromUtf8("Процесс"), process);
    form->addRow(QString::fromUtf8("Назначение"), target);
    form->addRow(QString::fromUtf8("Порты"), ports);
    form->addRow(QString::fromUtf8("Действие"), action);
    form->addRow(QString::fromUtf8("Прокси"), proxy);
    form->addRow(QString::fromUtf8("Цепочка"), chain);
    form->addRow(QString::fromUtf8("Комментарий"), comment);
    auto *layout = new QVBoxLayout(&dialog);
    layout->addLayout(form);
    layout->addWidget(buttons(&dialog));
    auto sync = [=] {
        const auto kind = RuleAction(action->currentData().toInt());
        proxy->setEnabled(kind == RuleAction::Proxy);
        chain->setEnabled(kind == RuleAction::Chain);
    };
    QObject::connect(action, &QComboBox::currentIndexChanged, &dialog, sync);
    sync();
    if (dialog.exec() != QDialog::Accepted)
        return false;
    if (!portsSpecValid(ports->text())) {
        warn(parent, QString::fromUtf8("Порты задайте как 80,443 или 1000-2000."));
        return false;
    }
    const auto kind = RuleAction(action->currentData().toInt());
    if (kind == RuleAction::Proxy && proxy->currentIndex() < 0) {
        warn(parent, QString::fromUtf8("Сначала добавьте прокси."));
        return false;
    }
    if (kind == RuleAction::Chain && chain->currentIndex() < 0) {
        warn(parent, QString::fromUtf8("Сначала добавьте цепочку."));
        return false;
    }
    rule.enabled = enabled->isChecked();
    rule.process = process->text().trimmed();
    rule.target = target->text().trimmed();
    rule.ports = ports->text().trimmed();
    rule.action = kind;
    rule.proxyId = proxy->currentData().toString();
    rule.chainId = chain->currentData().toString();
    rule.comment = comment->text().trimmed();
    if (rule.id.isEmpty())
        rule.id = newId();
    return true;
}

bool pickProxy(QWidget *parent, const AppConfig &config, const QString &service, QString *proxyId)
{
    if (!proxyId)
        return false;
    if (config.proxies.isEmpty()) {
        warn(parent, QString::fromUtf8("Сначала добавьте прокси на вкладке «Прокси»."));
        return false;
    }
    QDialog dialog(parent);
    dialog.setWindowTitle(service.isEmpty() ? QString::fromUtf8("Выбор прокси")
                                            : QString::fromUtf8("Прокси для %1").arg(service));
    dialog.resize(420, 160);
    auto *proxyBox = new QComboBox;
    for (const Proxy &item : config.proxies)
        proxyBox->addItem(item.name, item.id);
    const int current = proxyBox->findData(*proxyId);
    if (current >= 0)
        proxyBox->setCurrentIndex(current);
    auto *detail = new QLabel(service.isEmpty()
                                  ? QString::fromUtf8("Выберите прокси.")
                                  : QString::fromUtf8("Для «%1» прокси ещё не выбран.").arg(service));
    detail->setWordWrap(true);
    auto *form = new QFormLayout;
    form->addRow(QString::fromUtf8("Прокси"), proxyBox);
    auto *layout = new QVBoxLayout(&dialog);
    layout->addWidget(detail);
    layout->addLayout(form);
    layout->addWidget(buttons(&dialog));
    if (dialog.exec() != QDialog::Accepted || proxyBox->currentIndex() < 0)
        return false;
    *proxyId = proxyBox->currentData().toString();
    return !proxyId->isEmpty();
}

bool editChain(QWidget *parent, Chain &chain, const AppConfig &config)
{
    QDialog dialog(parent);
    dialog.setWindowTitle(QString::fromUtf8("Цепочка прокси"));
    dialog.resize(420, 360);
    auto *name = new QLineEdit(chain.name);
    auto *list = new QListWidget;
    for (const QString &id : chain.proxyIds) {
        for (const Proxy &proxy : config.proxies) {
            if (proxy.id == id) {
                auto *item = new QListWidgetItem(proxy.name);
                item->setData(Qt::UserRole, proxy.id);
                list->addItem(item);
            }
        }
    }
    auto *pick = new QComboBox;
    for (const Proxy &proxy : config.proxies)
        pick->addItem(proxy.name, proxy.id);
    auto *add = new QPushButton(QString::fromUtf8("Добавить"));
    auto *remove = new QPushButton(QString::fromUtf8("Убрать"));
    auto *up = new QPushButton(QString::fromUtf8("Выше"));
    auto *down = new QPushButton(QString::fromUtf8("Ниже"));
    QObject::connect(add, &QPushButton::clicked, &dialog, [=] {
        if (pick->currentIndex() < 0)
            return;
        auto *item = new QListWidgetItem(pick->currentText());
        item->setData(Qt::UserRole, pick->currentData());
        list->addItem(item);
    });
    QObject::connect(remove, &QPushButton::clicked, &dialog, [=] {
        delete list->takeItem(list->currentRow());
    });
    QObject::connect(up, &QPushButton::clicked, &dialog, [=] {
        const int row = list->currentRow();
        if (row > 0)
            list->insertItem(row - 1, list->takeItem(row));
    });
    QObject::connect(down, &QPushButton::clicked, &dialog, [=] {
        const int row = list->currentRow();
        if (row >= 0 && row < list->count() - 1) {
            auto *item = list->takeItem(row);
            list->insertItem(row + 1, item);
            list->setCurrentRow(row + 1);
        }
    });
    auto *row = new QHBoxLayout;
    row->addWidget(pick);
    row->addWidget(add);
    auto *side = new QVBoxLayout;
    side->addWidget(remove);
    side->addWidget(up);
    side->addWidget(down);
    side->addStretch();
    auto *mid = new QHBoxLayout;
    mid->addWidget(list);
    mid->addLayout(side);
    auto *form = new QFormLayout;
    form->addRow(QString::fromUtf8("Имя"), name);
    auto *layout = new QVBoxLayout(&dialog);
    layout->addLayout(form);
    layout->addLayout(row);
    layout->addLayout(mid);
    layout->addWidget(buttons(&dialog));
    if (dialog.exec() != QDialog::Accepted)
        return false;
    if (name->text().trimmed().isEmpty() || list->count() == 0) {
        warn(parent, QString::fromUtf8("Нужны имя и хотя бы один прокси."));
        return false;
    }
    chain.name = name->text().trimmed();
    chain.proxyIds.clear();
    for (int i = 0; i < list->count(); ++i)
        chain.proxyIds.append(list->item(i)->data(Qt::UserRole).toString());
    if (chain.id.isEmpty())
        chain.id = newId();
    return true;
}

bool editSettings(QWidget *parent, AppConfig &config)
{
    QDialog dialog(parent);
    dialog.setWindowTitle(QString::fromUtf8("Настройки"));
    dialog.resize(480, 460);
    auto *host = new QLineEdit(config.listenHost);
    auto *socksPort = new QSpinBox;
    socksPort->setRange(1, 65535);
    socksPort->setValue(config.socksPort);
    auto *httpPort = new QSpinBox;
    httpPort->setRange(1, 65535);
    httpPort->setValue(config.httpPort);
    auto *socksOn = new QCheckBox(QString::fromUtf8("Слушать SOCKS5"));
    socksOn->setChecked(config.socksEnabled);
    auto *httpOn = new QCheckBox(QString::fromUtf8("Слушать HTTP-прокси"));
    httpOn->setChecked(config.httpEnabled);
    auto *remote = new QCheckBox(QString::fromUtf8("Отдавать DNS прокси, не резолвить локально"));
    remote->setChecked(config.remoteDns);
    auto *system = new QCheckBox(QString::fromUtf8("Ставить системный прокси Windows, пока маршрутизация включена"));
    system->setChecked(config.systemProxy);
    auto *autostart = new QCheckBox(QString::fromUtf8("Автозапуск с Windows"));
    autostart->setChecked(config.autostart);
    auto *limit = new QSpinBox;
    limit->setRange(200, 200000);
    limit->setValue(config.logLimit);
    auto *hotkey = new QKeySequenceEdit(QKeySequence(config.hotkey));
    auto *shieldOn = new QCheckBox(QString::fromUtf8("Принимать входящие соединения щита"));
    shieldOn->setIcon(QIcon(QStringLiteral(":/shield.ico")));
    shieldOn->setIconSize(QSize(18, 18));
    shieldOn->setChecked(config.shieldListen);
    auto *shieldHost = new QLineEdit(config.shieldListenHost);
    auto *shieldPort = new QSpinBox;
    shieldPort->setRange(1, 65535);
    shieldPort->setValue(config.shieldPort);
    auto *shieldPsk = new QLineEdit(config.shieldPsk);
    shieldPsk->setEchoMode(QLineEdit::Password);
    auto *hint = new QLabel(QString::fromUtf8(
        "Входящий щит по умолчанию только на localhost. На удалённой машине укажите 0.0.0.0 и тот же ключ, "
        "что в карточке прокси. Имя Яндекса или другого сайта — прикрытие для DPI, не адрес назначения."));
    hint->setWordWrap(true);
    auto *form = new QFormLayout;
    form->addRow(QString::fromUtf8("Адрес прослушивания"), host);
    form->addRow(QString::fromUtf8("Порт SOCKS"), socksPort);
    form->addRow(QString::fromUtf8("Порт HTTP"), httpPort);
    form->addRow(QString(), socksOn);
    form->addRow(QString(), httpOn);
    form->addRow(QString(), remote);
    form->addRow(QString(), system);
    form->addRow(QString(), autostart);
    form->addRow(QString::fromUtf8("Лимит строк журнала"), limit);
    form->addRow(QString::fromUtf8("Горячая клавиша"), hotkey);
    form->addRow(QString(), shieldOn);
    form->addRow(QString::fromUtf8("Адрес щита"), shieldHost);
    form->addRow(QString::fromUtf8("Порт щита"), shieldPort);
    form->addRow(QString::fromUtf8("Ключ щита"), shieldPsk);
    auto *layout = new QVBoxLayout(&dialog);
    layout->addLayout(form);
    layout->addWidget(hint);
    layout->addWidget(buttons(&dialog));
    if (dialog.exec() != QDialog::Accepted)
        return false;
    if (socksPort->value() == httpPort->value()
        || (shieldOn->isChecked() && (shieldPort->value() == socksPort->value() || shieldPort->value() == httpPort->value()))) {
        warn(parent, QString::fromUtf8("Порты SOCKS, HTTP и щита должны различаться."));
        return false;
    }
    if (shieldOn->isChecked() && shieldPsk->text().isEmpty()) {
        warn(parent, QString::fromUtf8("Для входящего щита нужен общий ключ."));
        return false;
    }
    config.listenHost = host->text().trimmed().isEmpty() ? QStringLiteral("127.0.0.1") : host->text().trimmed();
    config.socksPort = static_cast<quint16>(socksPort->value());
    config.httpPort = static_cast<quint16>(httpPort->value());
    config.socksEnabled = socksOn->isChecked();
    config.httpEnabled = httpOn->isChecked();
    config.remoteDns = remote->isChecked();
    config.systemProxy = system->isChecked();
    config.autostart = autostart->isChecked();
    config.logLimit = limit->value();
    config.hotkey = hotkey->keySequence().toString(QKeySequence::PortableText);
    config.shieldListen = shieldOn->isChecked();
    config.shieldListenHost = shieldHost->text().trimmed().isEmpty()
        ? QStringLiteral("127.0.0.1")
        : shieldHost->text().trimmed();
    config.shieldPort = static_cast<quint16>(shieldPort->value());
    config.shieldPsk = shieldPsk->text();
    return true;
}

} // namespace qpr
