#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef _WIN32_WINNT
#    define _WIN32_WINNT 0x0601
#  endif
#  include <winsock2.h>
#  include <windows.h>
#endif

#include "windivert.h"

#include "divert_win.h"

#include <cstring>

namespace {

using OpenFn = HANDLE(WINAPI *)(const char *, WINDIVERT_LAYER, INT16, UINT64);
using RecvFn = BOOL(WINAPI *)(HANDLE, void *, UINT, UINT *, WINDIVERT_ADDRESS *);
using SendFn = BOOL(WINAPI *)(HANDLE, const void *, UINT, UINT *, const WINDIVERT_ADDRESS *);
using ShutdownFn = BOOL(WINAPI *)(HANDLE, WINDIVERT_SHUTDOWN);
using CloseFn = BOOL(WINAPI *)(HANDLE);
using SetParamFn = BOOL(WINAPI *)(HANDLE, WINDIVERT_PARAM, UINT64);
using ParseFn = BOOL(WINAPI *)(const void *, UINT, PWINDIVERT_IPHDR *, PWINDIVERT_IPV6HDR *, UINT8 *,
                               PWINDIVERT_ICMPHDR *, PWINDIVERT_ICMPV6HDR *, PWINDIVERT_TCPHDR *,
                               PWINDIVERT_UDPHDR *, void **, UINT *, void **, UINT *);
using CalcFn = BOOL(WINAPI *)(void *, UINT, WINDIVERT_ADDRESS *, UINT64);

struct Api {
    HMODULE module = nullptr;
    OpenFn open = nullptr;
    RecvFn recv = nullptr;
    SendFn send = nullptr;
    ShutdownFn shutdown = nullptr;
    CloseFn close = nullptr;
    SetParamFn setParam = nullptr;
    ParseFn parse = nullptr;
    CalcFn calc = nullptr;
};

Api *apiOf(void *library)
{
    return static_cast<Api *>(library);
}

void stamp(WINDIVERT_ADDRESS *addr, const DivertMeta *meta, int rewrite)
{
    if (!rewrite) {
        std::memcpy(addr, meta->addr, sizeof(*addr));
        addr->Impostor = 1;
        return;
    }
    std::memset(addr, 0, sizeof(*addr));
    addr->Layer = WINDIVERT_LAYER_NETWORK;
    addr->Event = WINDIVERT_EVENT_NETWORK_PACKET;
    addr->Outbound = meta->outbound ? 1 : 0;
    addr->Loopback = meta->loopback ? 1 : 0;
    addr->Impostor = 1;
    addr->IPv6 = meta->ipv6 ? 1 : 0;
    addr->Network.IfIdx = meta->ifIdx;
    addr->Network.SubIfIdx = meta->subIfIdx;
}

} // namespace

void *divert_load(const wchar_t *dllPath)
{
    HMODULE module = LoadLibraryW(dllPath);
    if (!module)
        return nullptr;
    auto *api = new Api;
    api->open = reinterpret_cast<OpenFn>(GetProcAddress(module, "WinDivertOpen"));
    api->recv = reinterpret_cast<RecvFn>(GetProcAddress(module, "WinDivertRecv"));
    api->send = reinterpret_cast<SendFn>(GetProcAddress(module, "WinDivertSend"));
    api->shutdown = reinterpret_cast<ShutdownFn>(GetProcAddress(module, "WinDivertShutdown"));
    api->close = reinterpret_cast<CloseFn>(GetProcAddress(module, "WinDivertClose"));
    api->setParam = reinterpret_cast<SetParamFn>(GetProcAddress(module, "WinDivertSetParam"));
    api->parse = reinterpret_cast<ParseFn>(GetProcAddress(module, "WinDivertHelperParsePacket"));
    api->calc = reinterpret_cast<CalcFn>(GetProcAddress(module, "WinDivertHelperCalcChecksums"));
    if (!api->open || !api->recv || !api->send || !api->shutdown || !api->close || !api->parse || !api->calc) {
        FreeLibrary(module);
        delete api;
        return nullptr;
    }
    api->module = module;
    return api;
}

void divert_unload(void *library)
{
    Api *api = apiOf(library);
    if (!api)
        return;
    if (api->module)
        FreeLibrary(api->module);
    delete api;
}

void *divert_open(void *library, const char *filter, int layer, unsigned long long flags, unsigned *error)
{
    Api *api = apiOf(library);
    HANDLE handle = api->open(filter, static_cast<WINDIVERT_LAYER>(layer), 0, flags);
    if (handle == INVALID_HANDLE_VALUE) {
        if (error)
            *error = GetLastError();
        return nullptr;
    }
    if (api->setParam) {
        api->setParam(handle, WINDIVERT_PARAM_QUEUE_LENGTH, 4096);
        api->setParam(handle, WINDIVERT_PARAM_QUEUE_TIME, 2000);
        api->setParam(handle, WINDIVERT_PARAM_QUEUE_SIZE, 4 * 1024 * 1024);
    }
    return handle;
}

void divert_shutdown(void *library, void *handle)
{
    if (library && handle)
        apiOf(library)->shutdown(handle, WINDIVERT_SHUTDOWN_RECV);
}

void divert_close(void *library, void *handle)
{
    if (library && handle)
        apiOf(library)->close(handle);
}

int divert_recv(void *library, void *handle, unsigned char *buffer, unsigned capacity, unsigned *length, DivertMeta *meta)
{
    WINDIVERT_ADDRESS addr;
    std::memset(&addr, 0, sizeof(addr));
    UINT received = 0;
    if (!apiOf(library)->recv(handle, buffer, capacity, &received, &addr))
        return 0;
    static_assert(sizeof(addr) <= DIVERT_ADDR_BYTES, "WinDivert address grew");
    std::memset(meta, 0, sizeof(*meta));
    std::memcpy(meta->addr, &addr, sizeof(addr));
    meta->outbound = addr.Outbound ? 1 : 0;
    meta->loopback = addr.Loopback ? 1 : 0;
    meta->ipv6 = addr.IPv6 ? 1 : 0;
    meta->ifIdx = addr.Network.IfIdx;
    meta->subIfIdx = addr.Network.SubIfIdx;
    *length = received;
    return 1;
}

int divert_send(void *library, void *handle, unsigned char *buffer, unsigned length, const DivertMeta *meta, int rewrite)
{
    WINDIVERT_ADDRESS addr;
    stamp(&addr, meta, rewrite);
    if (rewrite && !apiOf(library)->calc(buffer, length, &addr, 0))
        return 0;
    return apiOf(library)->send(handle, buffer, length, nullptr, &addr) ? 1 : 0;
}

int divert_parse(void *library, unsigned char *buffer, unsigned length,
                 unsigned char **ip4, unsigned char **ip6, unsigned char **tcp, unsigned char **udp)
{
    PWINDIVERT_IPHDR ipv4 = nullptr;
    PWINDIVERT_IPV6HDR ipv6 = nullptr;
    PWINDIVERT_TCPHDR tcpHdr = nullptr;
    PWINDIVERT_UDPHDR udpHdr = nullptr;
    if (!apiOf(library)->parse(buffer, length, &ipv4, &ipv6, nullptr, nullptr, nullptr, &tcpHdr,
                              &udpHdr, nullptr, nullptr, nullptr, nullptr))
        return 0;
    if (!tcpHdr && !udpHdr)
        return 0;
    *ip4 = reinterpret_cast<unsigned char *>(ipv4);
    *ip6 = reinterpret_cast<unsigned char *>(ipv6);
    *tcp = reinterpret_cast<unsigned char *>(tcpHdr);
    *udp = reinterpret_cast<unsigned char *>(udpHdr);
    return 1;
}

int divert_read_socket(const DivertMeta *meta, unsigned *event, unsigned *pid, unsigned *localPort,
                       unsigned *remotePort, unsigned *protocol)
{
    WINDIVERT_ADDRESS addr;
    std::memset(&addr, 0, sizeof(addr));
    std::memcpy(&addr, meta->addr, sizeof(addr));
    if (event)
        *event = addr.Event;
    if (pid)
        *pid = addr.Socket.ProcessId;
    if (localPort)
        *localPort = addr.Socket.LocalPort;
    if (remotePort)
        *remotePort = addr.Socket.RemotePort;
    if (protocol)
        *protocol = addr.Socket.Protocol;
    return addr.Socket.ProcessId != 0 && addr.Socket.LocalPort != 0;
}
