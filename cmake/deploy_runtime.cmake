if(NOT DEFINED TARGET_EXE OR NOT DEFINED QMAKE_EXE)
    return()
endif()

get_filename_component(_qt_bin "${QMAKE_EXE}" DIRECTORY)
find_program(_windeployqt NAMES windeployqt windeployqt6 HINTS "${_qt_bin}")
if(_windeployqt)
    execute_process(
        COMMAND "${_windeployqt}" --compiler-runtime --no-translations "${TARGET_EXE}"
        RESULT_VARIABLE _deploy_rc)
    if(NOT _deploy_rc EQUAL 0)
        message(WARNING "windeployqt завершился с кодом ${_deploy_rc}")
    endif()
endif()

get_filename_component(_dst "${TARGET_EXE}" DIRECTORY)
if(DEFINED OPENSSL_ROOT AND NOT OPENSSL_ROOT STREQUAL "")
    foreach(_name libcrypto-3-x64.dll libssl-3-x64.dll)
        if(EXISTS "${OPENSSL_ROOT}/bin/${_name}")
            execute_process(COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${OPENSSL_ROOT}/bin/${_name}" "${_dst}/${_name}")
        endif()
    endforeach()
endif()
