#pragma once

#include <QByteArray>
#include <QObject>
#include <QString>

namespace qpr {

struct AppConfig;

QString windowsZoneForIana(const QByteArray &iana);
QString acceptLanguagesForCountry(const QString &country);

class PrivacyGuard : public QObject {
public:
    explicit PrivacyGuard(QObject *parent = nullptr);
    ~PrivacyGuard() override;

    void recoverIfIdle(bool routingOff);
    void sync(const AppConfig &config, bool active);

private:
    void onExit(int generation, const QString &iana, const QString &ip, const QString &country, const QString &error);
    void applyExitLanguage(const QString &country);
    void applyWebrtc();
    void restoreWebrtc();
    void restoreTimezone();
    class Private;
    Private *d_;
};

} // namespace qpr
