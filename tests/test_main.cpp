#include "cidr.h"
#include "configstore.h"
#include "dialer.h"
#include "flow.h"
#include "inbound.h"
#include "presets.h"
#include "ruleengine.h"
#include "shieldcodec.h"
#include "shieldserver.h"
#include "socksutil.h"

#include <QCoreApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QHostAddress>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTimer>

#include <cstdio>
#include <functional>

namespace {

int g_failed = 0;

void check(bool condition, const char *text)
{
    if (condition)
        return;
    std::fprintf(stderr, "FAIL %s\n", text);
    ++g_failed;
}

bool spin(int ms, const std::function<bool()> &ready)
{
    QElapsedTimer timer;
    timer.start();
    while (timer.elapsed() < ms) {
        if (ready())
            return true;
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
    }
    return ready();
}

int testCidrAndPorts()
{
    const int before = g_failed;
    check(qpr::cidrContains(QStringLiteral("10.0.0.0/8"), QHostAddress(QStringLiteral("10.1.2.3"))), "cidr /8");
    check(!qpr::cidrContains(QStringLiteral("10.0.0.0/8"), QHostAddress(QStringLiteral("11.0.0.1"))), "cidr miss");
    check(qpr::cidrContains(QStringLiteral("192.168.1.9/32"), QHostAddress(QStringLiteral("192.168.1.9"))), "cidr /32");
    check(qpr::portsMatch(QStringLiteral("80,443,1000-1002"), 443), "port list");
    check(qpr::portsMatch(QStringLiteral("80,443,1000-1002"), 1001), "port range");
    check(!qpr::portsMatch(QStringLiteral("80,443"), 53), "port miss");
    check(qpr::portsSpecValid(QStringLiteral("80,1000-2000")), "ports valid");
    check(!qpr::portsSpecValid(QStringLiteral("80-")), "ports invalid");
    return g_failed - before;
}

int testRules()
{
    const int before = g_failed;
    qpr::AppConfig config;
    config.routingEnabled = true;
    qpr::Rule block;
    block.id = QStringLiteral("b");
    block.process = QStringLiteral("foo.exe");
    block.action = qpr::RuleAction::Block;
    qpr::Rule allow;
    allow.id = QStringLiteral("a");
    allow.process = QStringLiteral("*");
    allow.action = qpr::RuleAction::Direct;
    config.rules = {block, allow};
    qpr::Endpoint endpoint;
    endpoint.process = QStringLiteral("FOO.EXE");
    endpoint.host = QStringLiteral("1.2.3.4");
    endpoint.port = 80;
    qpr::Decision decision = qpr::matchRules(config, endpoint);
    check(decision.action == qpr::RuleAction::Block, "first rule wins");
    endpoint.process = QStringLiteral("bar.exe");
    decision = qpr::matchRules(config, endpoint);
    check(decision.action == qpr::RuleAction::Direct, "second rule");

    qpr::Rule cidr;
    cidr.target = QStringLiteral("10.0.0.0/8");
    cidr.action = qpr::RuleAction::Block;
    cidr.process = QStringLiteral("*");
    config.rules = {cidr};
    endpoint.host = QStringLiteral("example.com");
    endpoint.ip = {};
    decision = qpr::matchRules(config, endpoint);
    check(decision.needIp, "cidr needs ip");
    endpoint.ip = QHostAddress(QStringLiteral("10.9.9.9"));
    decision = qpr::matchRules(config, endpoint);
    check(decision.action == qpr::RuleAction::Block && !decision.needIp, "cidr matches after resolve");

    qpr::Proxy first;
    first.id = QStringLiteral("p1");
    first.name = QStringLiteral("one");
    qpr::Proxy second;
    second.id = QStringLiteral("p2");
    second.name = QStringLiteral("two");
    config.proxies = {first, second};
    qpr::Chain chain;
    chain.id = QStringLiteral("c");
    chain.proxyIds = {first.id, second.id};
    config.chains = {chain};
    qpr::Rule via;
    via.action = qpr::RuleAction::Chain;
    via.chainId = chain.id;
    via.process = QStringLiteral("*");
    config.rules = {via};
    decision = qpr::matchRules(config, endpoint);
    check(decision.hops.size() == 2 && decision.hops.first().id == QStringLiteral("p1"), "chain order");
    check(qpr::wildMatch(QStringLiteral("fire*.exe"), QStringLiteral("firefox.exe")), "wildcard");

    qpr::Rule youtube;
    youtube.id = QStringLiteral("yt");
    youtube.builtin = QStringLiteral("youtube");
    youtube.process = QStringLiteral("*");
    youtube.enabled = true;
    youtube.action = qpr::RuleAction::Proxy;
    youtube.proxyId = first.id;
    const qpr::SocialNet *ytNet = qpr::socialNet(QStringLiteral("youtube"));
    check(ytNet && !ytNet->domains.isEmpty() && !ytNet->nets.isEmpty(), "youtube list");
    youtube.target = qpr::socialTarget(*ytNet);
    config.rules = {youtube};
    endpoint.process = QStringLiteral("firefox.exe");
    endpoint.host = QStringLiteral("www.youtube.com");
    endpoint.ip = {};
    decision = qpr::matchRules(config, endpoint);
    check(decision.action == qpr::RuleAction::Proxy && decision.hops.size() == 1, "youtube name");
    endpoint.host = QStringLiteral("mail.google.com");
    decision = qpr::matchRules(config, endpoint);
    check(decision.needIp, "youtube nets need an address");
    decision = qpr::matchRules(config, endpoint, true);
    check(decision.action == qpr::RuleAction::Direct && !decision.needIp, "unresolved name skips nets");
    qpr::Rule earlierNets;
    earlierNets.id = QStringLiteral("ig");
    earlierNets.builtin = QStringLiteral("instagram");
    earlierNets.process = QStringLiteral("*");
    earlierNets.enabled = true;
    earlierNets.action = qpr::RuleAction::Proxy;
    earlierNets.proxyId = first.id;
    const qpr::SocialNet *igNet = qpr::socialNet(QStringLiteral("instagram"));
    earlierNets.target = qpr::socialTarget(*igNet);
    config.rules = {earlierNets, youtube};
    endpoint.host = QStringLiteral("www.youtube.com");
    endpoint.ip = {};
    decision = qpr::matchRules(config, endpoint);
    check(decision.action == qpr::RuleAction::Proxy && decision.ruleId == youtube.id && !decision.needIp,
          "youtube name wins over earlier nets");
    qpr::Rule firefox;
    firefox.id = QStringLiteral("ff");
    firefox.process = QStringLiteral("firefox.exe");
    firefox.action = qpr::RuleAction::Proxy;
    firefox.proxyId = second.id;
    firefox.enabled = true;
    config.rules = {earlierNets, youtube, firefox};
    endpoint.host = QStringLiteral("example.com");
    decision = qpr::matchRules(config, endpoint);
    check(decision.needIp, "catch-all waits for an address");
    decision = qpr::matchRules(config, endpoint, true);
    check(decision.action == qpr::RuleAction::Proxy && decision.ruleId == firefox.id, "unresolved falls to firefox");
    qpr::Rule telegram;
    telegram.builtin = QStringLiteral("telegram");
    telegram.process = QStringLiteral("*");
    telegram.enabled = true;
    telegram.action = qpr::RuleAction::Proxy;
    telegram.proxyId = first.id;
    telegram.target = qpr::socialTarget(*qpr::socialNet(QStringLiteral("telegram")));
    config.rules = {telegram};
    endpoint.process = QStringLiteral("firefox.exe");
    endpoint.host = QStringLiteral("149.154.167.41");
    endpoint.ip = QHostAddress(endpoint.host);
    decision = qpr::matchRules(config, endpoint);
    check(decision.action == qpr::RuleAction::Proxy, "telegram net");
    qpr::AppConfig socialConfig;
    qpr::Rule named;
    named.id = QStringLiteral("old-yt");
    named.comment = QString::fromUtf8("YouTube");
    named.proxyId = first.id;
    named.enabled = true;
    named.action = qpr::RuleAction::Proxy;
    named.process = QStringLiteral("*");
    named.target = QStringLiteral("youtube.com");
    qpr::Rule nets;
    nets.comment = QString::fromUtf8("YouTube — сети");
    nets.proxyId = second.id;
    nets.enabled = true;
    nets.action = qpr::RuleAction::Proxy;
    socialConfig.rules = {named, nets, firefox};
    check(qpr::ensureSocialRules(socialConfig), "social rules installed");
    int youtubeRows = 0;
    bool youtubeKept = false;
    bool firefoxKept = false;
    for (const qpr::Rule &rule : socialConfig.rules) {
        if (rule.builtin == QStringLiteral("youtube")) {
            ++youtubeRows;
            youtubeKept = rule.id == named.id && rule.proxyId == first.id && rule.enabled;
        }
        if (rule.process == QStringLiteral("firefox.exe"))
            firefoxKept = true;
    }
    check(youtubeRows == 1 && youtubeKept && firefoxKept, "preset rows become one switch");
    check(!qpr::ensureSocialRules(socialConfig), "social rules stay put");
    return g_failed - before;
}

int testShieldCodec()
{
    const int before = g_failed;
    const QByteArray hello = qpr::buildClientHello(QStringLiteral("ya.ru"));
    check(qpr::extractSni(hello) == QStringLiteral("ya.ru"), "sni is cover name");
    check(!hello.contains("1.2.3.4"), "hello has no destination ip");
    QByteArray random;
    const QByteArray server = qpr::buildServerHello(hello.mid(5), &random);
    check(random.size() == 32, "server random");
    check(qpr::serverRandomFromHandshake(server.mid(5)) == random, "random echo");
    check(qpr::authPrefixMatches(qpr::authPrefix(random), random), "auth prefix");

    QString error;
    const QByteArray key = qpr::deriveKey(QStringLiteral("test-secret"), &error);
    check(key.size() == 32, "key length");
    const QByteArray record = qpr::wrapAppData(key, QByteArrayLiteral("payload"), &error);
    QByteArray plain;
    check(qpr::unwrapAppData(key, record.mid(5), &plain, &error) && plain == QByteArrayLiteral("payload"), "roundtrip");
    QByteArray tampered = record;
    tampered[10] = char(tampered[10] ^ 0x5a);
    check(!qpr::unwrapAppData(key, tampered.mid(5), &plain, &error), "tamper rejected");

    QByteArray stream;
    stream.append(qpr::encodeFrame(qpr::FramePing, QByteArrayLiteral("ab")));
    const QByteArray full = stream;
    stream = full.left(3);
    QVector<qpr::Frame> frames;
    check(qpr::decodeFrames(stream, frames, &error) && frames.isEmpty(), "partial frame");
    stream.append(full.mid(3));
    check(qpr::decodeFrames(stream, frames, &error) && frames.size() == 1 && frames[0].type == qpr::FramePing, "frame done");
    QString host;
    quint16 port = 0;
    const QByteArray body = qpr::connectPayload(QStringLiteral("example.com"), 443);
    check(qpr::parseConnectPayload(body, &host, &port) && host == QStringLiteral("example.com") && port == 443, "connect payload");

    const QByteArray request = qpr::socks5ConnectRequest(QStringLiteral("1.2.3.4"), 80);
    int consumed = 0;
    qpr::Socks5Reply reply;
    const qpr::ParseStatus status = qpr::parseSocks5Reply(request, &consumed, &reply, &error);
    check(status == qpr::ParseStatus::Ok && reply.host == QStringLiteral("1.2.3.4") && reply.port == 80, "socks address");
    const QByteArray udp = qpr::socksUdpPacket(QStringLiteral("ya.ru"), 53, QByteArrayLiteral("dns"));
    QByteArray dns;
    check(qpr::parseSocksUdpPacket(udp, &host, &port, &dns, &error) == qpr::ParseStatus::Ok
              && host == QStringLiteral("ya.ru") && dns == QByteArrayLiteral("dns"),
          "socks udp");
    return g_failed - before;
}

int testConfig()
{
    const int before = g_failed;
    qpr::AppConfig config;
    qpr::Proxy proxy;
    proxy.id = QStringLiteral("1");
    proxy.name = QStringLiteral("home");
    proxy.password = QStringLiteral("super-secret");
    proxy.shieldPsk = QStringLiteral("shield-secret");
    config.proxies.append(proxy);
    const QString path = QDir::temp().filePath(QStringLiteral("myipproxy-test-config.json"));
    QString error;
    check(qpr::ConfigStore::save(path, config, &error), "save config");
    const QString raw = QString::fromUtf8(QFile(path).readAll()); // file not opened
    QFile file(path);
    check(file.open(QIODevice::ReadOnly), "open config");
    const QString text = QString::fromUtf8(file.readAll());
    file.close();
    check(!text.contains(QStringLiteral("super-secret")), "password sealed");
    check(!text.contains(QStringLiteral("shield-secret")), "psk sealed");
    const qpr::AppConfig loaded = qpr::ConfigStore::load(path, &error);
    check(loaded.proxies.size() == 1 && loaded.proxies.first().password == QStringLiteral("super-secret"), "password roundtrip");
    check(loaded.proxies.first().shieldPsk == QStringLiteral("shield-secret"), "psk roundtrip");
    QFile::remove(path);
    QFile::remove(path + QStringLiteral(".bak"));
    Q_UNUSED(raw);
    return g_failed - before;
}

int testLiveTunnel()
{
    const int before = g_failed;
    QTcpServer echo;
    check(echo.listen(QHostAddress::LocalHost, 0), "echo listen");
    QObject::connect(&echo, &QTcpServer::newConnection, &echo, [&echo] {
        while (echo.hasPendingConnections()) {
            auto *socket = echo.nextPendingConnection();
            QObject::connect(socket, &QTcpSocket::readyRead, socket, [socket] {
                socket->write(socket->readAll());
            });
        }
    });

    qpr::ShieldServer shield;
    shield.setPsk(QStringLiteral("test-secret"));
    check(shield.listen(QHostAddress::LocalHost, 0), "shield listen");

    qpr::Proxy proxy;
    proxy.type = qpr::ProxyType::Shield;
    proxy.host = QStringLiteral("127.0.0.1");
    proxy.port = shield.port();
    proxy.shieldPsk = QStringLiteral("test-secret");
    proxy.coverHost = QStringLiteral("ya.ru");

    QByteArray got;
    QString failure;
    auto *dialer = new qpr::Dialer({proxy}, QStringLiteral("127.0.0.1"), echo.serverPort(), true);
    QObject::connect(dialer, &qpr::Dialer::established, dialer, [&](qpr::Pipe *pipe) {
        QObject::connect(pipe, &qpr::Pipe::bytes, dialer, [&](const QByteArray &data) { got += data; });
        pipe->goLive();
        pipe->write(QByteArrayLiteral("hello-shield"));
    });
    QObject::connect(dialer, &qpr::Dialer::failed, dialer, [&](const QString &error) { failure = error; });
    dialer->start();
    check(spin(8000, [&] { return got.contains(QByteArrayLiteral("hello-shield")) || !failure.isEmpty(); }), "shield wait");
    check(failure.isEmpty() && got.contains(QByteArrayLiteral("hello-shield")), "shield echo");
    if (!failure.isEmpty())
        std::fprintf(stderr, "  shield error: %s\n", failure.toUtf8().constData());
    dialer->deleteLater();

    failure.clear();
    proxy.shieldPsk = QStringLiteral("wrong-key");
    bool rejected = false;
    auto *bad = new qpr::Dialer({proxy}, QStringLiteral("127.0.0.1"), echo.serverPort(), true);
    QObject::connect(bad, &qpr::Dialer::failed, bad, [&](const QString &) { rejected = true; });
    QObject::connect(bad, &qpr::Dialer::established, bad, [&](qpr::Pipe *) { failure = QStringLiteral("wrong key was accepted"); });
    bad->start();
    check(spin(8000, [&] { return rejected || !failure.isEmpty(); }), "bad key wait");
    check(rejected && failure.isEmpty(), "bad key rejected");
    bad->deleteLater();

    proxy.shieldPsk = QStringLiteral("test-secret");
    qpr::InboundServer inbound;
    qpr::InboundServer::Hooks hooks;
    hooks.prepare = [proxy](qpr::Endpoint endpoint, std::function<void(qpr::Decision, qpr::Endpoint)> done) {
        qpr::Decision decision;
        decision.action = qpr::RuleAction::Proxy;
        decision.hops = {proxy};
        decision.summary = QStringLiteral("test");
        done(decision, endpoint);
    };
    hooks.makeFlow = [](qpr::FlowSnapshot snapshot) { return new qpr::Flow(std::move(snapshot)); };
    hooks.remoteDns = [] { return true; };
    inbound.setHooks(hooks);
    check(inbound.listenSocks(QHostAddress::LocalHost, 0), "socks listen");

    QTcpSocket client;
    QByteArray inbox;
    QObject::connect(&client, &QTcpSocket::readyRead, &client, [&] { inbox += client.readAll(); });
    client.connectToHost(QHostAddress::LocalHost, inbound.socksPort());
    check(spin(3000, [&] { return client.state() == QAbstractSocket::ConnectedState; }), "socks connected");
    client.write(QByteArray::fromHex("050100"));
    check(spin(3000, [&] { return inbox.size() >= 2; }), "socks greeting");
    check(inbox.left(2) == QByteArray::fromHex("0500"), "socks no-auth");
    inbox.clear();
    client.write(qpr::socks5ConnectRequest(QStringLiteral("127.0.0.1"), echo.serverPort()));
    check(spin(8000, [&] { return inbox.size() >= 10; }), "socks reply");
    check(quint8(inbox.at(1)) == 0x00, "socks success");
    inbox.clear();
    client.write(QByteArrayLiteral("via-socks"));
    check(spin(8000, [&] { return inbox.contains(QByteArrayLiteral("via-socks")); }), "socks echo");
    client.abort();
    return g_failed - before;
}

} // namespace

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    QCoreApplication::setOrganizationName(QStringLiteral("myIPproxy-test"));
    QCoreApplication::setApplicationName(QStringLiteral("myIPproxy-test"));
    qRegisterMetaType<qpr::Pipe *>("qpr::Pipe*");
    testCidrAndPorts();
    testRules();
    testShieldCodec();
    testConfig();
    testLiveTunnel();
    if (g_failed == 0) {
        std::printf("ok\n");
        return 0;
    }
    std::fprintf(stderr, "%d failed\n", g_failed);
    return 1;
}
