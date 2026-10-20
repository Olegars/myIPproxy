#include "logger.h"

#include <QCoreApplication>
#include <QMetaObject>
#include <QMutexLocker>
#include <QThread>

namespace qpr {

Logger *Logger::instance()
{
    static Logger *logger = new Logger;
    return logger;
}

Logger::Logger(QObject *parent)
    : QObject(parent)
{
}

void Logger::info(const QString &text) { log(LogLevel::Info, text); }
void Logger::warn(const QString &text) { log(LogLevel::Warning, text); }
void Logger::error(const QString &text) { log(LogLevel::Error, text); }

void Logger::setLimit(int limit)
{
    QMutexLocker lock(&mutex_);
    limit_ = qMax(100, limit);
    while (lines_.size() > limit_)
        lines_.removeFirst();
}

QList<Logger::Line> Logger::history() const
{
    QMutexLocker lock(&mutex_);
    return lines_;
}

void Logger::log(LogLevel level, const QString &text)
{
    if (!QCoreApplication::instance())
        return;
    const QDateTime time = QDateTime::currentDateTime();
    {
        QMutexLocker lock(&mutex_);
        Line line;
        line.level = level;
        line.time = time;
        line.text = text;
        lines_.append(line);
        while (lines_.size() > limit_)
            lines_.removeFirst();
    }
    if (QThread::currentThread() == thread()) {
        emit logged(level, time, text);
        return;
    }
    QMetaObject::invokeMethod(this, [this, level, time, text] {
        emit logged(level, time, text);
    }, Qt::QueuedConnection);
}

} // namespace qpr
