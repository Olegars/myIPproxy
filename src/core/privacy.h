#pragma once

#include <QByteArray>
#include <QObject>
#include <QString>

namespace qpr {

struct AppConfig;

QString windowsZoneForIana(const QByteArray &iana);

class PrivacyGuard : public QObject {
public:
    explicit PrivacyGuard(QObject *parent = nullptr);
    ~PrivacyGuard() override;

    void recoverIfIdle(bool routingOff);
    void sync(const AppConfig &config, bool active);

private:
    void onExit(int generation, const QString &iana, const QString &ip, const QString &error);
    void applyWebrtc();
    void restoreWebrtc();
    void restoreTimezone();
    class Private;
    Private *d_;
};

} // namespace qpr
