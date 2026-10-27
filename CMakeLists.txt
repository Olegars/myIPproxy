cmake_minimum_required(VERSION 3.16)

project(myIPproxy VERSION 0.9.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC OFF)

if(MINGW)
    add_compile_options(-finput-charset=UTF-8 -fexec-charset=UTF-8)
endif()
if(MSVC)
    add_compile_options(/utf-8)
endif()

find_package(Qt6 REQUIRED COMPONENTS Core Widgets Network)
if(MINGW AND NOT OPENSSL_ROOT_DIR AND EXISTS "C:/msys64/mingw64/include/openssl/ssl.h")
    set(OPENSSL_ROOT_DIR "C:/msys64/mingw64" CACHE PATH "OpenSSL из MSYS2: в комплекте Qt его нет")
endif()
find_package(OpenSSL REQUIRED)

set(CORE_SOURCES
    src/core/types.h
    src/core/logger.h
    src/core/logger.cpp
    src/core/crashlog.h
    src/core/crashlog.cpp
    src/core/secretstore.h
    src/core/secretstore.cpp
    src/core/cidr.h
    src/core/cidr.cpp
    src/core/ruleengine.h
    src/core/ruleengine.cpp
    src/core/presets.h
    src/core/presets.cpp
    src/core/shieldcodec.h
    src/core/shieldcodec.cpp
    src/core/socksutil.h
    src/core/socksutil.cpp
    src/core/dnscache.h
    src/core/dnscache.cpp
    src/core/pipe.h
    src/core/pipe.cpp
    src/core/handshakes.h
    src/core/handshakes.cpp
    src/core/dialer.h
    src/core/dialer.cpp
    src/core/divert_win.h
    src/core/divert_win.cpp
    src/core/divertor.h
    src/core/divertor.cpp
    src/core/flow.h
    src/core/flow.cpp
    src/core/inbound.h
    src/core/inbound.cpp
    src/core/udpassoc.h
    src/core/udpassoc.cpp
    src/core/shieldserver.h
    src/core/shieldserver.cpp
    src/core/configstore.h
    src/core/configstore.cpp
    src/core/platform.h
    src/core/platform.cpp
    src/core/engine.h
    src/core/engine.cpp
    src/core/hub.h
    src/core/hub.cpp
    src/core/killswitch.h
    src/core/killswitch.cpp
    src/core/proxytest.h
    src/core/proxytest.cpp
)

add_library(myipproxy_core STATIC ${CORE_SOURCES})
target_include_directories(myipproxy_core PUBLIC src/core ${CMAKE_SOURCE_DIR}/third_party/WinDivert)
if(MINGW)
    set_source_files_properties(src/core/divert_win.cpp PROPERTIES COMPILE_OPTIONS "-mms-bitfields")
endif()
target_link_libraries(myipproxy_core PUBLIC Qt6::Core Qt6::Network OpenSSL::Crypto)
if(WIN32)
    target_link_libraries(myipproxy_core PUBLIC ws2_32 iphlpapi crypt32 wininet advapi32 fwpuclnt)
endif()
target_compile_definitions(myipproxy_core PRIVATE
    QT_NO_CAST_FROM_ASCII
)

add_executable(myIPproxy WIN32
    src/main.cpp
    src/service.h
    src/service.cpp
    src/ui/mainwindow.h
    src/ui/mainwindow.cpp
    src/ui/dialogs.h
    src/ui/dialogs.cpp
    resources/icons.qrc
    resources/app.rc
)
target_include_directories(myIPproxy PRIVATE src src/ui src/core)
target_link_libraries(myIPproxy PRIVATE myipproxy_core Qt6::Widgets)
target_compile_definitions(myIPproxy PRIVATE QT_NO_CAST_FROM_ASCII)
set_target_properties(myIPproxy PROPERTIES OUTPUT_NAME stopRKN)
if(WIN32)
    get_target_property(_qmake_exe Qt6::qmake IMPORTED_LOCATION)
    add_custom_command(TARGET myIPproxy POST_BUILD
        COMMAND ${CMAKE_COMMAND}
            -DSRC=${CMAKE_SOURCE_DIR}/third_party/WinDivert
            -DDST=$<TARGET_FILE_DIR:myIPproxy>
            -P ${CMAKE_SOURCE_DIR}/cmake/copy_windivert.cmake
        COMMAND ${CMAKE_COMMAND}
            -DTARGET_EXE=$<TARGET_FILE:myIPproxy>
            -DQMAKE_EXE=${_qmake_exe}
            -DOPENSSL_ROOT=${OPENSSL_ROOT_DIR}
            -P ${CMAKE_SOURCE_DIR}/cmake/deploy_runtime.cmake)
endif()

add_executable(myipproxy_tests
    tests/test_main.cpp
)
target_link_libraries(myipproxy_tests PRIVATE myipproxy_core Qt6::Core Qt6::Network)
target_compile_definitions(myipproxy_tests PRIVATE QT_NO_CAST_FROM_ASCII)

enable_testing()
add_test(NAME myipproxy_tests COMMAND myipproxy_tests)
