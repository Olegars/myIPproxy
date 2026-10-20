#pragma once

#include "types.h"

namespace qpr {

class ConfigStore {
public:
    static QString defaultPath();
    static bool needsMachinePromotion(const QString &path);
    static AppConfig load(const QString &path, QString *error = nullptr);
    static bool save(const QString &path, const AppConfig &config, QString *error = nullptr);
};

} // namespace qpr
