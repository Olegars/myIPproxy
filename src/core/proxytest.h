#pragma once

#include "types.h"

#include <QObject>
#include <functional>

namespace qpr {

void runProxyTest(const Proxy &proxy, QObject *parent, std::function<void(const QString &, bool)> done);
void runChainTest(const QList<Proxy> &hops, bool remoteDns, QObject *parent,
                  std::function<void(const QString &, bool)> done);

} // namespace qpr
