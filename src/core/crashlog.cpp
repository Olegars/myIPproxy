#include "crashlog.h"

#include <QByteArray>
#include <QtGlobal>

#include <csignal>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <exception>

#ifdef Q_OS_WIN
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef _WIN32_WINNT
#    define _WIN32_WINNT 0x0601
#  endif
#  include <windows.h>
#endif

namespace qpr {
namespace {

#ifdef Q_OS_WIN
constexpr wchar_t kDir[] = L"C:\\ProgramData\\stopRKN";
constexpr wchar_t kFile[] = L"C:\\ProgramData\\stopRKN\\error.log";
constexpr wchar_t kOld[] = L"C:\\ProgramData\\stopRKN\\error.log.1";

CRITICAL_SECTION g_lock;
bool g_lockReady = false;
volatile LONG g_crashWritten = 0;

void ensureDir()
{
    CreateDirectoryW(kDir, nullptr);
}

void writeFile(const char *level, const char *text, bool rotate)
{
    ensureDir();
    if (rotate) {
        WIN32_FILE_ATTRIBUTE_DATA info{};
        if (GetFileAttributesExW(kFile, GetFileExInfoStandard, &info)) {
            const ULONGLONG size = (ULONGLONG(info.nFileSizeHigh) << 32) | info.nFileSizeLow;
            if (size > 1024ULL * 1024ULL) {
                DeleteFileW(kOld);
                MoveFileW(kFile, kOld);
            }
        }
    }
    HANDLE file = CreateFileW(kFile, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
        return;
    LARGE_INTEGER size{};
    if (GetFileSizeEx(file, &size) && size.QuadPart == 0) {
        const unsigned char bom[] = {0xEF, 0xBB, 0xBF};
        DWORD wrote = 0;
        WriteFile(file, bom, sizeof(bom), &wrote, nullptr);
    }
    SYSTEMTIME now{};
    GetLocalTime(&now);
    char head[96];
    const int headLen = snprintf(head, sizeof(head), "%04u-%02u-%02u %02u:%02u:%02u  %-5s  ",
                                  now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond, level);
    DWORD wrote = 0;
    if (headLen > 0)
        WriteFile(file, head, DWORD(headLen), &wrote, nullptr);
    if (text && text[0])
        WriteFile(file, text, DWORD(strlen(text)), &wrote, nullptr);
    WriteFile(file, "\r\n", 2, &wrote, nullptr);
    FlushFileBuffers(file);
    CloseHandle(file);
}

void appendRaw(const char *level, const char *text, bool crash)
{
    if (!g_lockReady)
        return;
    bool locked = false;
    if (crash)
        locked = TryEnterCriticalSection(&g_lock);
    else {
        EnterCriticalSection(&g_lock);
        locked = true;
    }
    writeFile(level, text, locked && !crash);
    if (locked)
        LeaveCriticalSection(&g_lock);
}

const char *moduleOffset(void *address, char *out, size_t outLen)
{
    HMODULE module = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            static_cast<LPCWSTR>(address), &module)) {
        snprintf(out, outLen, "%p", address);
        return out;
    }
    wchar_t path[MAX_PATH];
    if (!GetModuleFileNameW(module, path, MAX_PATH)) {
        snprintf(out, outLen, "%p", address);
        return out;
    }
    const wchar_t *base = path;
    for (const wchar_t *p = path; *p; ++p) {
        if (*p == L'\\' || *p == L'/')
            base = p + 1;
    }
    char name[128];
    WideCharToMultiByte(CP_UTF8, 0, base, -1, name, int(sizeof(name)), nullptr, nullptr);
    const auto offset = reinterpret_cast<uintptr_t>(address) - reinterpret_cast<uintptr_t>(module);
    snprintf(out, outLen, "%s+0x%llx", name, static_cast<unsigned long long>(offset));
    return out;
}

void writeCrash(const char *text)
{
    if (InterlockedCompareExchange(&g_crashWritten, 1, 0) != 0)
        return;
    appendRaw("CRASH", text, true);
}

LONG WINAPI onUnhandled(EXCEPTION_POINTERS *info)
{
    char text[1400];
    text[0] = 0;
    DWORD code = 0;
    void *at = nullptr;
    if (info && info->ExceptionRecord) {
        code = info->ExceptionRecord->ExceptionCode;
        at = info->ExceptionRecord->ExceptionAddress;
    }
    char where[160];
    moduleOffset(at, where, sizeof(where));
    int len = snprintf(text, sizeof(text), "код 0x%08lX по адресу %s", static_cast<unsigned long>(code), where);
    if (code == 0xC0000005 && info && info->ExceptionRecord && info->ExceptionRecord->NumberParameters >= 2) {
        const ULONG_PTR op = info->ExceptionRecord->ExceptionInformation[0];
        const ULONG_PTR addr = info->ExceptionRecord->ExceptionInformation[1];
        const char *how = op == 1 ? "запись" : (op == 8 ? "исполнение" : "чтение");
        len += snprintf(text + len, sizeof(text) - size_t(len), ", %s %p", how, reinterpret_cast<void *>(addr));
    }
    void *frames[24];
    const USHORT count = CaptureStackBackTrace(0, 24, frames, nullptr);
    for (USHORT i = 0; i < count && len > 0 && size_t(len) + 80 < sizeof(text); ++i) {
        char frame[160];
        moduleOffset(frames[i], frame, sizeof(frame));
        len += snprintf(text + len, sizeof(text) - size_t(len), "%s%s", i == 0 ? " | " : " <- ", frame);
    }
    writeCrash(text);
    return EXCEPTION_CONTINUE_SEARCH;
}

void onTerminate()
{
    const char *what = "необработанное исключение C++";
    try {
        if (std::current_exception()) {
            try {
                std::rethrow_exception(std::current_exception());
            } catch (const std::exception &error) {
                what = error.what();
            } catch (...) {
                what = "необработанное исключение не std::exception";
            }
        }
    } catch (...) {
    }
    char text[800];
    snprintf(text, sizeof(text), "%s", what ? what : "");
    writeCrash(text);
    std::abort();
}

void onSignal(int sig)
{
    char text[1400];
    int len = snprintf(text, sizeof(text), "сигнал %d", sig);
    void *frames[16];
    const USHORT count = CaptureStackBackTrace(0, 16, frames, nullptr);
    for (USHORT i = 0; i < count && len > 0 && size_t(len) + 80 < sizeof(text); ++i) {
        char frame[160];
        moduleOffset(frames[i], frame, sizeof(frame));
        len += snprintf(text + len, sizeof(text) - size_t(len), "%s%s", i == 0 ? " | " : " <- ", frame);
    }
    writeCrash(text);
    std::signal(sig, SIG_DFL);
    std::raise(sig);
}

void onPure()
{
    writeCrash("вызов чистой виртуальной функции");
}

void onInvalid(const wchar_t *, const wchar_t *, const wchar_t *, unsigned int, uintptr_t)
{
    writeCrash("недопустимый параметр CRT");
}

void qtMessage(QtMsgType type, const QMessageLogContext &, const QString &message)
{
    if (type != QtCriticalMsg && type != QtFatalMsg)
        return;
    CrashLog::write(type == QtFatalMsg ? QStringLiteral("FATAL") : QStringLiteral("QT"), message);
    if (type == QtFatalMsg)
        std::abort();
}
#endif

} // namespace

void CrashLog::install()
{
#ifdef Q_OS_WIN
    static bool once = false;
    if (once)
        return;
    once = true;
    InitializeCriticalSection(&g_lock);
    g_lockReady = true;
    SetUnhandledExceptionFilter(onUnhandled);
    std::set_terminate(onTerminate);
    std::signal(SIGABRT, onSignal);
    std::signal(SIGSEGV, onSignal);
    _set_purecall_handler(onPure);
    _set_invalid_parameter_handler(onInvalid);
#else
    std::set_terminate([] { std::abort(); });
#endif
}

void CrashLog::installQt()
{
#ifdef Q_OS_WIN
    qInstallMessageHandler(qtMessage);
#else
    Q_UNUSED(0);
#endif
}

void CrashLog::write(const QString &level, const QString &text)
{
#ifdef Q_OS_WIN
    const QByteArray lvl = level.toUtf8();
    QByteArray body = text.toUtf8();
    body.replace('\r', ' ');
    body.replace('\n', ' ');
    if (body.size() > 2000)
        body.truncate(2000);
    appendRaw(lvl.constData(), body.constData(), false);
#else
    Q_UNUSED(level);
    Q_UNUSED(text);
#endif
}

QString CrashLog::path()
{
#ifdef Q_OS_WIN
    return QStringLiteral("C:/ProgramData/stopRKN/error.log");
#else
    return {};
#endif
}

} // namespace qpr
