@echo off
setlocal
set PATH=C:\msys64\mingw64\bin;%PATH%
cmake -S "%~dp0." -B "%~dp0build" -G Ninja -DCMAKE_PREFIX_PATH=C:/msys64/mingw64 -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER=C:/msys64/mingw64/bin/g++.exe
if errorlevel 1 exit /b 1
cmake --build "%~dp0build" --parallel
if errorlevel 1 exit /b 1
windeployqt6 --compiler-runtime --no-translations "%~dp0build\stopRKN.exe"
copy /Y "C:\msys64\mingw64\bin\libgcc_s_seh-1.dll" "%~dp0build\" >nul
copy /Y "C:\msys64\mingw64\bin\libstdc++-6.dll" "%~dp0build\" >nul
copy /Y "C:\msys64\mingw64\bin\libwinpthread-1.dll" "%~dp0build\" >nul
copy /Y "C:\msys64\mingw64\bin\libcrypto-3-x64.dll" "%~dp0build\" >nul
copy /Y "C:\msys64\mingw64\bin\libssl-3-x64.dll" "%~dp0build\" >nul
exit /b 0
