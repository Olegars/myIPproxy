@echo off
setlocal EnableDelayedExpansion
set "QT_ROOT=C:\Qt_new\6.12.0\msvc2022_64"
set "OPENSSL_ROOT=C:\Qt\openssl"
set "CMAKE=C:\Qt_new\Tools\CMake_64\bin\cmake.exe"
set "NINJA_DIR=C:\Qt_new\Tools\Ninja"
set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"

if not exist "!QT_ROOT!\bin\qmake.exe" (
    echo Qt not found: !QT_ROOT!
    exit /b 1
)
if not exist "!OPENSSL_ROOT!\include\openssl\ssl.h" (
    echo OpenSSL not found: !OPENSSL_ROOT!
    exit /b 1
)
if not exist "!VCVARS!" (
    echo MSVC Build Tools not found: !VCVARS!
    exit /b 1
)
call "!VCVARS!"
if errorlevel 1 exit /b 1
set "PATH=!NINJA_DIR!;!QT_ROOT!\bin;!PATH!"

findstr /I /C:"mingw" /C:"msys" "%~dp0build\CMakeCache.txt" >nul 2>&1
if not errorlevel 1 (
    echo Removing old MSYS2 build
    rmdir /s /q "%~dp0build"
)

set "QT_PREFIX=!QT_ROOT:\=/!"
set "SSL_PREFIX=!OPENSSL_ROOT:\=/!"
"!CMAKE!" -S "%~dp0." -B "%~dp0build" -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="!QT_PREFIX!" -DOPENSSL_ROOT_DIR="!SSL_PREFIX!"
if errorlevel 1 exit /b 1
"!CMAKE!" --build "%~dp0build" --parallel
if errorlevel 1 exit /b 1
exit /b 0
