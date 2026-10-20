#pragma once

#include "types.h"

namespace qpr {

struct SocialNet {
    QString id;
    QString title;
    QString domains;
    QString nets;
};

const QList<SocialNet> &socialNets();
const SocialNet *socialNet(const QString &id);
QString socialTarget(const SocialNet &net);
bool ensureSocialRules(AppConfig &config);

} // namespace qpr
