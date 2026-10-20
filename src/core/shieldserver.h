#pragma once

#include <QHostAddress>
#include <QObject>
#include <QString>

class QTcpServer;

namespace qpr {

class ShieldServer : public QObject {
    Q_OBJECT
public:
    explicit ShieldServer(QObject *parent = nullptr);
    void setPsk(const QString &psk);
    bool listen(const QHostAddress &address, quint16 port);
    void closeListener();
    quint16 port() const;
    bool listening() const;

private:
    void accept();

    QString psk_;
    QTcpServer *server_ = nullptr;
};

} // namespace qpr
