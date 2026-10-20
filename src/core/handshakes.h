#pragma once

#include "pipe.h"
#include "types.h"

#include <functional>

namespace qpr {

void handshakeSocks5(Pipe *pipe, const QString &user, const QString &password,
                     const QString &host, quint16 port,
                     std::function<void(const QString &error)> done);

void handshakeSocks4(Pipe *pipe, const QString &host, quint16 port, bool domainName,
                     std::function<void(const QString &error)> done);

void handshakeHttp(Pipe *pipe, const QString &user, const QString &password,
                   const QString &host, quint16 port,
                   std::function<void(const QString &error)> done);

void handshakeShield(Pipe *pipe, const QString &host, quint16 port,
                     std::function<void(Pipe *stream, const QString &error)> done);

} // namespace qpr
