#pragma once

#include <QHostAddress>
#include <QString>

namespace qpr {

struct ProcInfo {
    quint32 pid = 0;
    QString name;
};

ProcInfo processForPeer(const QHostAddress &address, quint16 port, quint16 localPort = 0, bool refresh = false);
ProcInfo processForUdp(quint16 localPort, bool ipv6, bool refresh = false);
QString processNameForPid(quint32 pid);
void setAutostart(bool enabled);
bool autostartEnabled();
bool proxyServiceInstalled();
bool proxyServiceRunning();
bool startProxyService(QString *error = nullptr, int waitMs = 8000);
bool installProxyService(QString *error);
bool uninstallProxyService(QString *error);

class SystemProxy {
public:
    bool enable(const QString &host, quint16 port);
    void restore();
    bool active() const { return active_; }

private:
    void publish() const;
    bool active_ = false;
    int oldEnable_ = 0;
    QString oldServer_;
    QString oldOverride_;
    bool haveOldOverride_ = false;
};

} // namespace qpr
