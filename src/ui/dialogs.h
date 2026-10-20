#pragma once

#include "types.h"

#include <QWidget>

namespace qpr {

bool editProxy(QWidget *parent, Proxy &proxy);
bool editRule(QWidget *parent, Rule &rule, const AppConfig &config);
bool pickProxy(QWidget *parent, const AppConfig &config, const QString &service, QString *proxyId);
bool editChain(QWidget *parent, Chain &chain, const AppConfig &config);
bool editSettings(QWidget *parent, AppConfig &config);

} // namespace qpr
