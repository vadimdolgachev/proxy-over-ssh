cmake_minimum_required(VERSION 4.1)
project(proxy_over_ssh)

set(CMAKE_CXX_STANDARD 23)

add_subdirectory(third_party/coro_lite)

include(cmake/CPM.cmake)

CPMAddPackage(
        NAME openssl-cmake
        GITHUB_REPOSITORY janbar/openssl-cmake
        GIT_TAG master
        OPTIONS
        "BUILD_SHARED_LIBS OFF"
        "WITH_APPS OFF"
        "CMAKE_POSITION_INDEPENDENT_CODE ON"
)

set(OPENSSL_ROOT_DIR ${openssl-cmake_BINARY_DIR})
set(OPENSSL_INCLUDE_DIR ${openssl-cmake_BINARY_DIR}/include)

if (ANDROID)
    set(OPENSSL_SSL_LIBRARY ${openssl-cmake_BINARY_DIR}/ssl/libssl_1_1.a)
    set(OPENSSL_CRYPTO_LIBRARY ${openssl-cmake_BINARY_DIR}/crypto/libcrypto_1_1.a)
else ()
    set(OPENSSL_SSL_LIBRARY ${openssl-cmake_BINARY_DIR}/ssl/libssl.a)
    set(OPENSSL_CRYPTO_LIBRARY ${openssl-cmake_BINARY_DIR}/crypto/libcrypto.a)
endif ()

add_library(OpenSSL::SSL STATIC IMPORTED GLOBAL)
set_target_properties(OpenSSL::SSL PROPERTIES
        IMPORTED_LOCATION ${OPENSSL_SSL_LIBRARY}
        INTERFACE_INCLUDE_DIRECTORIES ${OPENSSL_INCLUDE_DIR}
)

add_library(OpenSSL::Crypto STATIC IMPORTED GLOBAL)
set_target_properties(OpenSSL::Crypto PROPERTIES
        IMPORTED_LOCATION ${OPENSSL_CRYPTO_LIBRARY}
        INTERFACE_INCLUDE_DIRECTORIES ${OPENSSL_INCLUDE_DIR}
)

CPMAddPackage(
        NAME libssh2
        GITHUB_REPOSITORY libssh2/libssh2
        GIT_TAG libssh2-1.11.1
        OPTIONS
        "CMAKE_POLICY_VERSION_MINIMUM 3.5"
        "BUILD_EXAMPLES OFF"
        "BUILD_TESTING OFF"
        "BUILD_SHARED_LIBS OFF"
        "BUILD_STATIC_LIBS ON"
        "CMAKE_POSITION_INDEPENDENT_CODE ON"
        "ENABLE_ZLIB_COMPRESSION ON"
        "CRYPTO_BACKEND OpenSSL"
        "OPENSSL_ROOT_DIR ${OPENSSL_ROOT_DIR}"
)

add_executable(proxy_over_ssh main.cpp
        SSHProxy.cpp
        SSHProxy.h
        SshSocket.cpp
        SshSocket.h
        HttpConnect.cpp
        HttpConnect.h
        SessionPool.cpp
        SessionPool.h
        IdleTimer.h
        SshSessionHandler.h
        SshSessionHandler.cpp
        SshHostKey.cpp
        SshHostKey.h
)
target_link_libraries(proxy_over_ssh PRIVATE
        CoroLite::coro_lite
        OpenSSL::Crypto
        OpenSSL::SSL
        libssh2
)
add_dependencies(proxy_over_ssh crypto ssl)
target_compile_options(proxy_over_ssh PRIVATE -Wall -Wextra -Wpedantic -Werror -Wshadow -Wconversion -Wsign-conversion -Wnull-dereference -Wno-unused-variable -Wno-unused-parameter -Wno-unused-private-field -Werror=uninitialized -Wno-unused-function -fno-omit-frame-pointer)

#sudo sysctl vm.mmap_rnd_bits=30

target_compile_options(proxy_over_ssh PRIVATE
        $<$<STREQUAL:${SANITIZER},address>:-fsanitize=address>
        $<$<STREQUAL:${SANITIZER},thread>:-fsanitize=thread>
        $<$<OR:$<STREQUAL:${SANITIZER},address>,$<STREQUAL:${SANITIZER},thread>>:-O1>
)

target_link_options(proxy_over_ssh PRIVATE
        $<$<STREQUAL:${SANITIZER},address>:-fsanitize=address>
        $<$<STREQUAL:${SANITIZER},thread>:-fsanitize=thread>
)

if (ANDROID)
    message("ANDROID_ABI=${ANDROID_ABI}")
    message("ANDROID_NDK=${ANDROID_NDK}")
    message("ANDROID_NATIVE_API_LEVEL=${ANDROID_NATIVE_API_LEVEL}")
    message("ANDROID_PLATFORM=${ANDROID_PLATFORM}")
    target_link_libraries(proxy_over_ssh PRIVATE dl z log android)
endif ()

option(PROXY_BUILD_TESTS "Build proxy unit tests" OFF)
if (PROXY_BUILD_TESTS AND NOT ANDROID)
    enable_testing()
    add_executable(http_connect_test
            tests/HttpConnectTest.cpp
            HttpConnect.cpp
    )
    target_include_directories(http_connect_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(http_connect_test PRIVATE CoroLite::coro_lite)
    target_compile_options(http_connect_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
    target_compile_options(http_connect_test PRIVATE
            $<$<STREQUAL:${SANITIZER},address>:-fsanitize=address>
            $<$<STREQUAL:${SANITIZER},thread>:-fsanitize=thread>
    )
    target_link_options(http_connect_test PRIVATE
            $<$<STREQUAL:${SANITIZER},address>:-fsanitize=address>
            $<$<STREQUAL:${SANITIZER},thread>:-fsanitize=thread>
    )
    add_test(NAME http_connect COMMAND http_connect_test)

    add_executable(ssh_host_key_test
            tests/SshHostKeyTest.cpp
            SshHostKey.cpp
    )
    target_include_directories(ssh_host_key_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_compile_options(ssh_host_key_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
    target_compile_options(ssh_host_key_test PRIVATE
            $<$<STREQUAL:${SANITIZER},address>:-fsanitize=address>
            $<$<STREQUAL:${SANITIZER},thread>:-fsanitize=thread>
    )
    target_link_options(ssh_host_key_test PRIVATE
            $<$<STREQUAL:${SANITIZER},address>:-fsanitize=address>
            $<$<STREQUAL:${SANITIZER},thread>:-fsanitize=thread>
    )
    target_link_libraries(ssh_host_key_test PRIVATE OpenSSL::Crypto)
    add_dependencies(ssh_host_key_test crypto)
    add_test(NAME ssh_host_key COMMAND ssh_host_key_test)
endif ()
