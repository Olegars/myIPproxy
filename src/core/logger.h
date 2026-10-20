#pragma once

#include "types.h"

#include <QDateTime>
#include <QMutex>
#include <QObject>

namespace qpr {

class Logger : public QObject {
    Q_OBJECT
public:
    struct Line {
        LogLevel level = LogLevel::Info;
        QDateTime time;
        QString text;
    };

    static Logger *instance();

    void info(const QString &text);
    void warn(const QString &text);
    void error(const QString &text);
    void setLimit(int limit);
    QList<Line> history() const;

signals:
    void logged(qpr::LogLevel level, const QDateTime &time, const QString &text);

private:
    explicit Logger(QObject *parent = nullptr);
    void log(LogLevel level, const QString &text);

    QList<Line> lines_;
    int limit_ = 5000;
    mutable QMutex mutex_;
};

} // namespace qpr
