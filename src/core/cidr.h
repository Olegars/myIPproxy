#pragma once

#include <QHostAddress>
#include <QString>

namespace qpr {

bool isIpAddress(const QString &text);
bool cidrContains(const QString &cidr, const QHostAddress &ip);
bool portsMatch(const QString &spec, quint16 port);
bool portsSpecValid(const QString &spec);

} // namespace qpr
