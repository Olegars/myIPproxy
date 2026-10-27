#include "killswitch.h"

#include "logger.h"

#include <cstring>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef _WIN32_WINNT
#    define _WIN32_WINNT 0x0601
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
#  include <fwpmu.h>
#endif

namespace qpr {
namespace {

#ifdef _WIN32
HANDLE g_engine = nullptr;

GUID id(unsigned n)
{
    GUID key{0x4c1e91a0, 0x7b32, 0x4d55, {0x9e, 0x10, 0x2a, 0x6b, 0x80, 0xc3, 0x00, 0x00}};
    key.Data4[6] = static_cast<unsigned char>((n >> 8) & 0xff);
    key.Data4[7] = static_cast<unsigned char>(n & 0xff);
    return key;
}

const GUID kProvider = id(1);
const GUID kSublayer = id(2);

void addFilter(const GUID &key, const GUID &layer, UINT8 weight, FWP_ACTION_TYPE action, bool persistent,
               FWPM_FILTER_CONDITION0 *conds, UINT32 count)
{
    if (!g_engine)
        return;
    FWPM_FILTER0 filter{};
    filter.filterKey = key;
    filter.displayData.name = const_cast<wchar_t *>(L"stopRKN");
    filter.displayData.description = const_cast<wchar_t *>(persistent
                                                               ? L"stopRKN: закрыть интернет, если служба упала"
                                                               : L"stopRKN: служба работает");
    filter.flags = persistent ? FWPM_FILTER_FLAG_PERSISTENT : 0;
    filter.providerKey = const_cast<GUID *>(&kProvider);
    filter.layerKey = layer;
    filter.subLayerKey = kSublayer;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = weight;
    filter.numFilterConditions = count;
    filter.filterCondition = conds;
    filter.action.type = action;
    const DWORD err = FwpmFilterAdd0(g_engine, &filter, nullptr, nullptr);
    if (err != ERROR_SUCCESS && err != FWP_E_ALREADY_EXISTS)
        Logger::instance()->error(QString::fromUtf8("Не удалось записать фильтр сети, код %1").arg(err));
}

void permitRange4(unsigned keyNo, const GUID &layer, UINT32 lo, UINT32 hi)
{
    FWP_RANGE0 range{};
    range.valueLow.type = FWP_UINT32;
    range.valueLow.uint32 = lo;
    range.valueHigh.type = FWP_UINT32;
    range.valueHigh.uint32 = hi;
    FWPM_FILTER_CONDITION0 cond{};
    cond.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    cond.matchType = FWP_MATCH_RANGE;
    cond.conditionValue.type = FWP_RANGE_TYPE;
    cond.conditionValue.rangeValue = &range;
    addFilter(id(keyNo), layer, 12, FWP_ACTION_PERMIT, true, &cond, 1);
}

void permitPort(unsigned keyNo, const GUID &layer, UINT16 port)
{
    FWPM_FILTER_CONDITION0 conds[2]{};
    conds[0].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
    conds[0].matchType = FWP_MATCH_EQUAL;
    conds[0].conditionValue.type = FWP_UINT8;
    conds[0].conditionValue.uint8 = IPPROTO_UDP;
    conds[1].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
    conds[1].matchType = FWP_MATCH_EQUAL;
    conds[1].conditionValue.type = FWP_UINT16;
    conds[1].conditionValue.uint16 = port;
    addFilter(id(keyNo), layer, 12, FWP_ACTION_PERMIT, true, conds, 2);
}

void permitRange6(unsigned keyNo, const GUID &layer, const UINT8 lo[16], const UINT8 hi[16])
{
    FWP_BYTE_ARRAY16 low{};
    FWP_BYTE_ARRAY16 high{};
    memcpy(low.byteArray16, lo, 16);
    memcpy(high.byteArray16, hi, 16);
    FWP_RANGE0 range{};
    range.valueLow.type = FWP_BYTE_ARRAY16_TYPE;
    range.valueLow.byteArray16 = &low;
    range.valueHigh.type = FWP_BYTE_ARRAY16_TYPE;
    range.valueHigh.byteArray16 = &high;
    FWPM_FILTER_CONDITION0 cond{};
    cond.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    cond.matchType = FWP_MATCH_RANGE;
    cond.conditionValue.type = FWP_RANGE_TYPE;
    cond.conditionValue.rangeValue = &range;
    addFilter(id(keyNo), layer, 12, FWP_ACTION_PERMIT, true, &cond, 1);
}

void fill6(UINT8 out[16], UINT8 a, UINT8 b, bool top)
{
    memset(out, top ? 0xff : 0x00, 16);
    out[0] = a;
    out[1] = b;
}

bool openEngine()
{
    if (g_engine)
        return true;
    FWPM_SESSION0 session{};
    session.displayData.name = const_cast<wchar_t *>(L"stopRKN");
    const DWORD err = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, &session, &g_engine);
    if (err != ERROR_SUCCESS) {
        Logger::instance()->error(QString::fromUtf8("Фильтр сети не открылся, код %1").arg(err));
        g_engine = nullptr;
        return false;
    }
    return true;
}
#endif

} // namespace

void armKillSwitch()
{
#ifdef _WIN32
    if (!openEngine())
        return;
    FWPM_PROVIDER0 provider{};
    provider.providerKey = kProvider;
    provider.displayData.name = const_cast<wchar_t *>(L"stopRKN");
    provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;
    DWORD err = FwpmProviderAdd0(g_engine, &provider, nullptr);
    if (err != ERROR_SUCCESS && err != FWP_E_ALREADY_EXISTS) {
        Logger::instance()->error(QString::fromUtf8("Поставщик фильтра не записался, код %1").arg(err));
        return;
    }
    FWPM_SUBLAYER0 sublayer{};
    sublayer.subLayerKey = kSublayer;
    sublayer.displayData.name = const_cast<wchar_t *>(L"stopRKN");
    sublayer.providerKey = const_cast<GUID *>(&kProvider);
    sublayer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
    sublayer.weight = 0x100;
    err = FwpmSubLayerAdd0(g_engine, &sublayer, nullptr);
    if (err != ERROR_SUCCESS && err != FWP_E_ALREADY_EXISTS) {
        Logger::instance()->error(QString::fromUtf8("Слой фильтра не записался, код %1").arg(err));
        return;
    }

    const GUID v4[] = {FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_OUTBOUND_TRANSPORT_V4};
    const GUID v6[] = {FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_OUTBOUND_TRANSPORT_V6};
    unsigned n = 10;
    for (const GUID &layer : v4) {
        const UINT32 local[][2] = {
            {0x0A000000u, 0x0AFFFFFFu},
            {0xAC100000u, 0xAC1FFFFFu},
            {0xC0A80000u, 0xC0A8FFFFu},
            {0x7F000000u, 0x7FFFFFFFu},
            {0xA9FE0000u, 0xA9FEFFFFu},
            {0xE0000000u, 0xEFFFFFFFu},
            {0xFFFFFFFFu, 0xFFFFFFFFu},
        };
        for (const auto &span : local)
            permitRange4(n++, layer, span[0], span[1]);
        permitPort(n++, layer, 67);
        permitPort(n++, layer, 68);
        addFilter(id(n++), layer, 2, FWP_ACTION_BLOCK, true, nullptr, 0);
        addFilter(id(n++), layer, 15, FWP_ACTION_PERMIT, false, nullptr, 0);
    }
    UINT8 lo[16];
    UINT8 hi[16];
    for (const GUID &layer : v6) {
        fill6(lo, 0xfe, 0x80, false);
        fill6(hi, 0xfe, 0xbf, true);
        permitRange6(n++, layer, lo, hi);
        fill6(lo, 0xfc, 0x00, false);
        fill6(hi, 0xfd, 0xff, true);
        permitRange6(n++, layer, lo, hi);
        fill6(lo, 0xff, 0x00, false);
        fill6(hi, 0xff, 0xff, true);
        permitRange6(n++, layer, lo, hi);
        UINT8 loop[16]{};
        loop[15] = 1;
        permitRange6(n++, layer, loop, loop);
        permitPort(n++, layer, 546);
        permitPort(n++, layer, 547);
        addFilter(id(n++), layer, 2, FWP_ACTION_BLOCK, true, nullptr, 0);
        addFilter(id(n++), layer, 15, FWP_ACTION_PERMIT, false, nullptr, 0);
    }
    Logger::instance()->info(QString::fromUtf8(
        "Если служба упадёт, выход в интернет закроется. Локальная сеть останется."));
#else
#endif
}

void disarmKillSwitch()
{
#ifdef _WIN32
    const bool openedHere = g_engine == nullptr;
    if (!openEngine())
        return;
    for (unsigned n = 10; n < 80; ++n) {
        const GUID key = id(n);
        FwpmFilterDeleteByKey0(g_engine, &key);
    }
    FwpmSubLayerDeleteByKey0(g_engine, &kSublayer);
    FwpmProviderDeleteByKey0(g_engine, &kProvider);
    FwpmEngineClose0(g_engine);
    g_engine = nullptr;
    if (!openedHere)
        Logger::instance()->info(QString::fromUtf8("Служба остановлена, выход в интернет снова открыт."));
#else
#endif
}

} // namespace qpr
