#pragma once

#include "types.h"

namespace qpr {

Decision matchRules(const AppConfig &config, const Endpoint &endpoint, bool unresolvedCidrMiss = false);
QString describeVia(const Decision &decision);
bool wildMatch(const QString &pattern, const QString &text);
bool isWebRtcProcess(const QString &process);
bool blockDirectUdp(const AppConfig &config, const QString &process);
QList<Proxy> timezoneExitHops(const AppConfig &config);

} // namespace qpr
