get_filename_component(BYEDPI_ROOT "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)
set(BYEDPI_SOURCE_DIR "${BYEDPI_ROOT}/third_party/byedpi")

add_library(byedpi_engine STATIC
        ${BYEDPI_ROOT}/byedpi/Engine.c
        ${BYEDPI_SOURCE_DIR}/main.c
        ${BYEDPI_SOURCE_DIR}/proxy.c
        ${BYEDPI_SOURCE_DIR}/conev.c
        ${BYEDPI_SOURCE_DIR}/desync.c
        ${BYEDPI_SOURCE_DIR}/extend.c
        ${BYEDPI_SOURCE_DIR}/mpool.c
        ${BYEDPI_SOURCE_DIR}/packets.c
)
set_target_properties(byedpi_engine PROPERTIES
        C_STANDARD 99
        POSITION_INDEPENDENT_CODE ON
        C_VISIBILITY_PRESET hidden
)
target_include_directories(byedpi_engine PRIVATE ${BYEDPI_SOURCE_DIR})
target_compile_definitions(byedpi_engine PRIVATE _DEFAULT_SOURCE BYEDPI_EMBEDDED)
if (ANDROID)
    target_compile_definitions(byedpi_engine PRIVATE ANDROID_APP)
    target_link_libraries(byedpi_engine PRIVATE log)
endif ()
target_compile_options(byedpi_engine PRIVATE -Wall -Wextra -Wno-unused-parameter -Wno-unused-function)

find_package(Threads REQUIRED)
add_library(byedpi_runtime STATIC
        ${BYEDPI_ROOT}/ByeDpiRuntime.cpp
        ${BYEDPI_ROOT}/Socks5Client.cpp
        ${BYEDPI_ROOT}/byedpi/Arguments.cpp
)
set_target_properties(byedpi_runtime PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(byedpi_runtime PUBLIC ${BYEDPI_ROOT})
target_link_libraries(byedpi_runtime PUBLIC CoroLite::coro_lite PRIVATE byedpi_engine Threads::Threads)
target_compile_options(byedpi_runtime PRIVATE
        -Wall -Wextra -Wpedantic -Werror -Wshadow -Wconversion -Wsign-conversion
)
foreach(target byedpi_engine byedpi_runtime)
    target_compile_options(${target} PRIVATE
            $<$<STREQUAL:${SANITIZER},address>:-fsanitize=address>
            $<$<STREQUAL:${SANITIZER},thread>:-fsanitize=thread>
            $<$<OR:$<STREQUAL:${SANITIZER},address>,$<STREQUAL:${SANITIZER},thread>>:-O1>
    )
    target_link_options(${target} INTERFACE
            $<$<STREQUAL:${SANITIZER},address>:-fsanitize=address>
            $<$<STREQUAL:${SANITIZER},thread>:-fsanitize=thread>
    )
endforeach()
