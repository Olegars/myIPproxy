#include "shieldcodec.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <QRandomGenerator>

namespace qpr {
namespace {

void appendU8(QByteArray &out, quint8 value)
{
    out.append(static_cast<char>(value));
}

void appendU16(QByteArray &out, quint16 value)
{
    out.append(static_cast<char>((value >> 8) & 0xff));
    out.append(static_cast<char>(value & 0xff));
}

void appendU24(QByteArray &out, quint32 value)
{
    out.append(static_cast<char>((value >> 16) & 0xff));
    out.append(static_cast<char>((value >> 8) & 0xff));
    out.append(static_cast<char>(value & 0xff));
}

QByteArray randomBytes(int size)
{
    QByteArray out(size, 0);
    if (RAND_bytes(reinterpret_cast<unsigned char *>(out.data()), size) == 1)
        return out;
    auto *gen = QRandomGenerator::global();
    for (int i = 0; i < size; ++i)
        out[i] = static_cast<char>(gen->generate() & 0xff);
    return out;
}

quint16 readU16(const QByteArray &buf, int offset)
{
    return (quint16(quint8(buf.at(offset))) << 8) | quint16(quint8(buf.at(offset + 1)));
}

} // namespace

QByteArray deriveKey(const QString &psk, QString *error)
{
    if (psk.isEmpty()) {
        if (error)
            *error = QString::fromUtf8("пустой ключ щита");
        return {};
    }
    const QByteArray pass = psk.toUtf8();
    const QByteArray salt = QByteArrayLiteral("myIPproxy-shield-v1");
    QByteArray out(32, 0);
    const int rc = PKCS5_PBKDF2_HMAC(
        pass.constData(), pass.size(),
        reinterpret_cast<const unsigned char *>(salt.constData()), salt.size(),
        10000, EVP_sha256(), out.size(),
        reinterpret_cast<unsigned char *>(out.data()));
    if (rc != 1) {
        if (error)
            *error = QString::fromUtf8("не удалось получить ключ");
        return {};
    }
    return out;
}

QByteArray buildClientHello(const QString &sni)
{
    const QByteArray host = sni.toLatin1();
    const QByteArray random = randomBytes(32);
    const QByteArray sessionId = randomBytes(32);
    const QByteArray keyShare = randomBytes(32);

    QByteArray body;
    appendU16(body, 0x0303);
    body.append(random);
    appendU8(body, static_cast<quint8>(sessionId.size()));
    body.append(sessionId);

    QByteArray ciphers;
    const quint16 suites[] = {0x1301, 0x1302, 0x1303, 0xc02f, 0xc030, 0xcca8};
    for (quint16 suite : suites)
        appendU16(ciphers, suite);
    appendU16(body, static_cast<quint16>(ciphers.size()));
    body.append(ciphers);
    appendU8(body, 1);
    appendU8(body, 0);

    QByteArray ext;
    {
        QByteArray entry;
        appendU8(entry, 0);
        appendU16(entry, static_cast<quint16>(host.size()));
        entry.append(host);
        QByteArray list;
        appendU16(list, static_cast<quint16>(entry.size()));
        list.append(entry);
        appendU16(ext, 0);
        appendU16(ext, static_cast<quint16>(list.size()));
        ext.append(list);
    }
    {
        QByteArray groups;
        appendU16(groups, 4);
        appendU16(groups, 0x001d);
        appendU16(groups, 0x0017);
        appendU16(ext, 10);
        appendU16(ext, static_cast<quint16>(groups.size()));
        ext.append(groups);
    }
    {
        QByteArray sigs;
        const quint16 algs[] = {0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601};
        appendU16(sigs, static_cast<quint16>(sizeof(algs)));
        for (quint16 alg : algs)
            appendU16(sigs, alg);
        appendU16(ext, 13);
        appendU16(ext, static_cast<quint16>(sigs.size()));
        ext.append(sigs);
    }
    {
        QByteArray versions;
        appendU8(versions, 4);
        appendU16(versions, 0x0304);
        appendU16(versions, 0x0303);
        appendU16(ext, 43);
        appendU16(ext, static_cast<quint16>(versions.size()));
        ext.append(versions);
    }
    {
        QByteArray entry;
        appendU16(entry, 0x001d);
        appendU16(entry, 32);
        entry.append(keyShare);
        QByteArray list;
        appendU16(list, static_cast<quint16>(entry.size()));
        list.append(entry);
        appendU16(ext, 51);
        appendU16(ext, static_cast<quint16>(list.size()));
        ext.append(list);
    }
    {
        QByteArray protos;
        const QByteArray h2 = QByteArrayLiteral("h2");
        const QByteArray http = QByteArrayLiteral("http/1.1");
        appendU8(protos, static_cast<quint8>(h2.size()));
        protos.append(h2);
        appendU8(protos, static_cast<quint8>(http.size()));
        protos.append(http);
        QByteArray list;
        appendU16(list, static_cast<quint16>(protos.size()));
        list.append(protos);
        appendU16(ext, 16);
        appendU16(ext, static_cast<quint16>(list.size()));
        ext.append(list);
    }

    appendU16(body, static_cast<quint16>(ext.size()));
    body.append(ext);

    QByteArray handshake;
    appendU8(handshake, 1);
    appendU24(handshake, static_cast<quint32>(body.size()));
    handshake.append(body);

    QByteArray record;
    appendU8(record, 22);
    appendU16(record, 0x0301);
    appendU16(record, static_cast<quint16>(handshake.size()));
    record.append(handshake);
    return record;
}

QByteArray buildServerHello(const QByteArray &clientHandshake, QByteArray *randomOut)
{
    QByteArray sessionId;
    if (clientHandshake.size() >= 39 && quint8(clientHandshake.at(0)) == 1) {
        const int sidLen = quint8(clientHandshake.at(38));
        if (sidLen >= 0 && sidLen <= 32 && clientHandshake.size() >= 39 + sidLen)
            sessionId = clientHandshake.mid(39, sidLen);
    }
    const QByteArray random = randomBytes(32);
    if (randomOut)
        *randomOut = random;

    QByteArray body;
    appendU16(body, 0x0303);
    body.append(random);
    appendU8(body, static_cast<quint8>(sessionId.size()));
    body.append(sessionId);
    appendU16(body, 0x1301);
    appendU8(body, 0);

    QByteArray ext;
    QByteArray ver;
    appendU16(ver, 0x0304);
    appendU16(ext, 43);
    appendU16(ext, static_cast<quint16>(ver.size()));
    ext.append(ver);
    appendU16(body, static_cast<quint16>(ext.size()));
    body.append(ext);

    QByteArray handshake;
    appendU8(handshake, 2);
    appendU24(handshake, static_cast<quint32>(body.size()));
    handshake.append(body);

    QByteArray record;
    appendU8(record, 22);
    appendU16(record, 0x0303);
    appendU16(record, static_cast<quint16>(handshake.size()));
    record.append(handshake);
    return record;
}

QString extractSni(const QByteArray &record)
{
    if (record.size() < 5 || quint8(record.at(0)) != 22)
        return {};
    const int hs = 5;
    if (record.size() < hs + 4 || quint8(record.at(hs)) != 1)
        return {};
    const int body = hs + 4;
    if (record.size() < body + 35)
        return {};
    const int sidLen = quint8(record.at(body + 34));
    int pos = body + 35 + sidLen;
    if (record.size() < pos + 2)
        return {};
    const int cipherLen = readU16(record, pos);
    pos += 2 + cipherLen;
    if (record.size() < pos + 1)
        return {};
    const int compLen = quint8(record.at(pos));
    pos += 1 + compLen;
    if (record.size() < pos + 2)
        return {};
    const int extLen = readU16(record, pos);
    pos += 2;
    const int end = qMin(record.size(), pos + extLen);
    while (pos + 4 <= end) {
        const int type = readU16(record, pos);
        const int len = readU16(record, pos + 2);
        pos += 4;
        if (pos + len > end)
            break;
        if (type == 0 && len >= 5) {
            const int nameType = quint8(record.at(pos + 2));
            const int nameLen = readU16(record, pos + 3);
            if (nameType == 0 && pos + 5 + nameLen <= pos + len)
                return QString::fromLatin1(record.mid(pos + 5, nameLen));
        }
        pos += len;
    }
    return {};
}

QByteArray serverRandomFromHandshake(const QByteArray &handshake)
{
    if (handshake.size() < 38 || quint8(handshake.at(0)) != 2)
        return {};
    return handshake.mid(6, 32);
}

QByteArray ccsRecord()
{
    return QByteArray::fromHex("140303000101");
}

void RecordBuffer::append(const QByteArray &bytes)
{
    if (!error_.isEmpty())
        return;
    buffer_.append(bytes);
}

void RecordBuffer::clear()
{
    buffer_.clear();
    error_.clear();
}

bool RecordBuffer::next(TlsRecord &record)
{
    if (!error_.isEmpty() || buffer_.size() < 5)
        return false;
    const quint8 type = quint8(buffer_.at(0));
    const int len = (quint8(buffer_.at(3)) << 8) | quint8(buffer_.at(4));
    if (len < 0 || len > 20000) {
        error_ = QString::fromUtf8("слишком большая TLS-запись");
        buffer_.clear();
        return false;
    }
    if (buffer_.size() < 5 + len)
        return false;
    record.type = type;
    record.payload = buffer_.mid(5, len);
    buffer_.remove(0, 5 + len);
    return true;
}

QByteArray wrapAppData(const QByteArray &key, const QByteArray &plain, QString *error)
{
    if (key.size() != 32) {
        if (error)
            *error = QString::fromUtf8("некорректный ключ");
        return {};
    }
    QByteArray iv = randomBytes(12);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        if (error)
            *error = QString::fromUtf8("нет шифра");
        return {};
    }
    QByteArray cipher(plain.size() + 16, 0);
    int len = 0;
    int total = 0;
    unsigned char tag[16];
    bool ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1
        && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1
        && EVP_EncryptInit_ex(ctx, nullptr, nullptr,
                              reinterpret_cast<const unsigned char *>(key.constData()),
                              reinterpret_cast<const unsigned char *>(iv.constData())) == 1
        && EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char *>(cipher.data()), &len,
                             reinterpret_cast<const unsigned char *>(plain.constData()),
                             plain.size()) == 1;
    total = len;
    int fin = 0;
    ok = ok && EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char *>(cipher.data()) + total, &fin) == 1;
    total += fin;
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) == 1;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) {
        if (error)
            *error = QString::fromUtf8("ошибка шифрования");
        return {};
    }
    cipher.resize(total);
    QByteArray packet;
    packet.append(iv);
    packet.append(cipher);
    packet.append(reinterpret_cast<const char *>(tag), 16);

    QByteArray record;
    appendU8(record, 23);
    appendU16(record, 0x0303);
    appendU16(record, static_cast<quint16>(packet.size()));
    record.append(packet);
    return record;
}

bool unwrapAppData(const QByteArray &key, const QByteArray &recordPayload, QByteArray *plain, QString *error)
{
    if (key.size() != 32 || recordPayload.size() < 28) {
        if (error)
            *error = QString::fromUtf8("неверный ключ или повреждённый пакет");
        return false;
    }
    const QByteArray iv = recordPayload.left(12);
    const QByteArray tag = recordPayload.right(16);
    const QByteArray cipher = recordPayload.mid(12, recordPayload.size() - 28);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        if (error)
            *error = QString::fromUtf8("нет шифра");
        return false;
    }
    QByteArray out(cipher.size() + 16, 0);
    int len = 0;
    int total = 0;
    bool ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1
        && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1
        && EVP_DecryptInit_ex(ctx, nullptr, nullptr,
                              reinterpret_cast<const unsigned char *>(key.constData()),
                              reinterpret_cast<const unsigned char *>(iv.constData())) == 1
        && EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char *>(out.data()), &len,
                             reinterpret_cast<const unsigned char *>(cipher.constData()),
                             cipher.size()) == 1;
    total = len;
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                                   const_cast<char *>(tag.constData())) == 1;
    int fin = 0;
    ok = ok && EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char *>(out.data()) + total, &fin) == 1;
    total += fin;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) {
        if (error)
            *error = QString::fromUtf8("неверный ключ или повреждённый пакет");
        return false;
    }
    out.resize(total);
    if (plain)
        *plain = out;
    return true;
}

QByteArray encodeFrame(quint8 type, const QByteArray &payload)
{
    QByteArray out;
    appendU8(out, type);
    const quint32 len = static_cast<quint32>(payload.size());
    out.append(static_cast<char>((len >> 24) & 0xff));
    out.append(static_cast<char>((len >> 16) & 0xff));
    out.append(static_cast<char>((len >> 8) & 0xff));
    out.append(static_cast<char>(len & 0xff));
    out.append(payload);
    return out;
}

bool decodeFrames(QByteArray &buffer, QVector<Frame> &out, QString *error)
{
    while (buffer.size() >= 5) {
        const quint8 type = quint8(buffer.at(0));
        const quint32 len = (quint32(quint8(buffer.at(1))) << 24)
            | (quint32(quint8(buffer.at(2))) << 16)
            | (quint32(quint8(buffer.at(3))) << 8)
            | quint32(quint8(buffer.at(4)));
        if (len > 8u * 1024u * 1024u) {
            if (error)
                *error = QString::fromUtf8("слишком большой кадр");
            buffer.clear();
            return false;
        }
        if (buffer.size() < 5 + int(len))
            return true;
        Frame frame;
        frame.type = type;
        frame.payload = buffer.mid(5, int(len));
        buffer.remove(0, 5 + int(len));
        out.append(frame);
    }
    return true;
}

QByteArray connectPayload(const QString &host, quint16 port)
{
    const QByteArray name = host.toUtf8();
    QByteArray out;
    appendU16(out, port);
    appendU16(out, static_cast<quint16>(qMin(name.size(), 65535)));
    out.append(name.left(65535));
    return out;
}

bool parseConnectPayload(const QByteArray &payload, QString *host, quint16 *port)
{
    if (payload.size() < 4)
        return false;
    const quint16 dstPort = readU16(payload, 0);
    const int hostLen = readU16(payload, 2);
    if (payload.size() < 4 + hostLen)
        return false;
    if (host)
        *host = QString::fromUtf8(payload.mid(4, hostLen));
    if (port)
        *port = dstPort;
    return true;
}

QByteArray authPrefix(const QByteArray &serverRandom)
{
    QByteArray out = QByteArrayLiteral("QPR1");
    out.append(serverRandom.left(32));
    return out;
}

bool authPrefixMatches(const QByteArray &plain, const QByteArray &serverRandom)
{
    if (plain.size() < 36 || serverRandom.size() != 32)
        return false;
    return plain.startsWith(QByteArrayLiteral("QPR1")) && plain.mid(4, 32) == serverRandom;
}

} // namespace qpr
