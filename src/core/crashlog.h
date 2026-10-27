#pragma once

#include <QString>

namespace qpr {

class CrashLog {
public:
    static void install();
    static void installQt();
    static void write(const QString &level, const QString &text);
    static QString path();
};

} // namespace qpr
