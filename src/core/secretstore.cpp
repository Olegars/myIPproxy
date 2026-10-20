#include "secretstore.h"

#include <QByteArray>

#ifdef Q_OS_WIN
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  include <wincrypt.h>
#endif

namespace qpr {

bool SecretStore::looksSealed(const QString &stored)
{
    return stored.startsWith(QLatin1String("dpapi:")) || stored.startsWith(QLatin1String("dpapim:"));
}

QString SecretStore::seal(const QString &plain)
{
    if (plain.isEmpty())
        return {};
#ifdef Q_OS_WIN
    const QByteArray utf = plain.toUtf8();
    DATA_BLOB in{};
    in.cbData = static_cast<DWORD>(utf.size());
    in.pbData = reinterpret_cast<BYTE *>(const_cast<char *>(utf.constData()));
    DATA_BLOB out{};
    if (!CryptProtectData(&in, L"myIPproxy", nullptr, nullptr, nullptr,
                          CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE, &out)) {
        return {};
    }
    const QByteArray raw(reinterpret_cast<const char *>(out.pbData), static_cast<int>(out.cbData));
    LocalFree(out.pbData);
    return QStringLiteral("dpapim:") + QString::fromLatin1(raw.toBase64());
#else
    return QStringLiteral("plain:") + QString::fromLatin1(plain.toUtf8().toBase64());
#endif
}

QString SecretStore::open(const QString &stored)
{
    if (stored.isEmpty())
        return {};
#ifdef Q_OS_WIN
    int offset = 0;
    if (stored.startsWith(QLatin1String("dpapim:")))
        offset = 7;
    else if (stored.startsWith(QLatin1String("dpapi:")))
        offset = 6;
    else
        return stored;
    const QByteArray raw = QByteArray::fromBase64(stored.mid(offset).toLatin1());
    if (raw.isEmpty())
        return {};
    DATA_BLOB in{};
    in.cbData = static_cast<DWORD>(raw.size());
    in.pbData = reinterpret_cast<BYTE *>(const_cast<char *>(raw.constData()));
    DATA_BLOB out{};
    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr,
                            CRYPTPROTECT_UI_FORBIDDEN, &out)) {
        return {};
    }
    const QString plain = QString::fromUtf8(reinterpret_cast<const char *>(out.pbData),
                                            static_cast<int>(out.cbData));
    LocalFree(out.pbData);
    return plain;
#else
    if (stored.startsWith(QLatin1String("plain:")))
        return QString::fromUtf8(QByteArray::fromBase64(stored.mid(6).toLatin1()));
    return stored;
#endif
}

} // namespace qpr
