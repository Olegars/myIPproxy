#pragma once

#include <QString>

namespace qpr {

class SecretStore {
public:
    static QString seal(const QString &plain);
    static QString open(const QString &stored);
    static bool looksSealed(const QString &stored);
};

} // namespace qpr
