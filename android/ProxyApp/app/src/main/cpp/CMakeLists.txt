cmake_minimum_required(VERSION 3.22.1)
project(proxyapp LANGUAGES C CXX ASM)

set(CMAKE_CXX_STANDARD 23)

get_filename_component(PROXY_OVER_SSH_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/../../../../../.."
    ABSOLUTE
)
message(STATUS "PROXY_OVER_SSH_DIR = ${PROXY_OVER_SSH_DIR}")

add_subdirectory(
        ${PROXY_OVER_SSH_DIR}/third_party/coro_lite
        ${CMAKE_CURRENT_BINARY_DIR}/coro_lite
)

include(ExternalProject)

find_program(PERL_EXECUTABLE perl REQUIRED)
find_program(MAKE_EXECUTABLE NAMES make gmake REQUIRED)

file(GLOB NDK_PREBUILT_DIRS LIST_DIRECTORIES true "${ANDROID_NDK}/toolchains/llvm/prebuilt/*")
list(LENGTH NDK_PREBUILT_DIRS NDK_PREBUILT_COUNT)
if (NOT NDK_PREBUILT_COUNT EQUAL 1)
    message(FATAL_ERROR "Expected one Android NDK host toolchain, found ${NDK_PREBUILT_COUNT}")
endif ()
list(GET NDK_PREBUILT_DIRS 0 NDK_PREBUILT_DIR)

if (ANDROID_ABI STREQUAL "arm64-v8a")
    set(OPENSSL_ANDROID_TARGET android-arm64)
elseif (ANDROID_ABI STREQUAL "armeabi-v7a")
    set(OPENSSL_ANDROID_TARGET android-arm)
else ()
    message(FATAL_ERROR "Unsupported Android ABI for OpenSSL: ${ANDROID_ABI}")
endif ()

string(REGEX REPLACE "^android-" "" OPENSSL_ANDROID_API "${ANDROID_PLATFORM}")
set(NATIVE_DEPS_DIR "${CMAKE_CURRENT_BINARY_DIR}/native-deps")
set(OPENSSL_INSTALL_DIR "${NATIVE_DEPS_DIR}/openssl")
set(LIBSSH2_INSTALL_DIR "${NATIVE_DEPS_DIR}/libssh2")
set(OPENSSL_INCLUDE_DIR "${OPENSSL_INSTALL_DIR}/include")
set(OPENSSL_SSL_LIBRARY "${OPENSSL_INSTALL_DIR}/lib/libssl.a")
set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_INSTALL_DIR}/lib/libcrypto.a")
set(LIBSSH2_INCLUDE_DIR "${LIBSSH2_INSTALL_DIR}/include")
set(LIBSSH2_LIBRARY "${LIBSSH2_INSTALL_DIR}/lib/libssh2.a")
file(MAKE_DIRECTORY "${OPENSSL_INCLUDE_DIR}" "${LIBSSH2_INCLUDE_DIR}")

ExternalProject_Add(openssl_android
        URL https://github.com/openssl/openssl/releases/download/openssl-3.5.7/openssl-3.5.7.tar.gz
        URL_HASH SHA256=a8c0d28a529ca480f9f36cf5792e2cd21984552a3c8e4aa11a24aa31aeac98e8
        PREFIX "${NATIVE_DEPS_DIR}/openssl-project"
        BINARY_DIR "${NATIVE_DEPS_DIR}/openssl-build"
        CONFIGURE_COMMAND
            ${CMAKE_COMMAND} -E env
            "ANDROID_NDK_ROOT=${ANDROID_NDK}"
            "PATH=${NDK_PREBUILT_DIR}/bin:$ENV{PATH}"
            ${PERL_EXECUTABLE} <SOURCE_DIR>/Configure
            ${OPENSSL_ANDROID_TARGET}
            -D__ANDROID_API__=${OPENSSL_ANDROID_API}
            -Wno-macro-redefined
            no-shared no-tests no-module
            --prefix=${OPENSSL_INSTALL_DIR}
            --openssldir=${OPENSSL_INSTALL_DIR}/ssl
            --libdir=lib
        BUILD_COMMAND
            ${CMAKE_COMMAND} -E env
            "ANDROID_NDK_ROOT=${ANDROID_NDK}"
            "PATH=${NDK_PREBUILT_DIR}/bin:$ENV{PATH}"
            ${MAKE_EXECUTABLE} -j4 build_sw
        INSTALL_COMMAND
            ${CMAKE_COMMAND} -E env
            "ANDROID_NDK_ROOT=${ANDROID_NDK}"
            "PATH=${NDK_PREBUILT_DIR}/bin:$ENV{PATH}"
            ${MAKE_EXECUTABLE} install_sw
        BUILD_BYPRODUCTS "${OPENSSL_CRYPTO_LIBRARY}" "${OPENSSL_SSL_LIBRARY}"
)

ExternalProject_Add(libssh2_android_project
        URL https://libssh2.org/download/libssh2-1.11.1.tar.gz
        URL_HASH SHA256=d9ec76cbe34db98eec3539fe2c899d26b0c837cb3eb466a56b0f109cabf658f7
        PREFIX "${NATIVE_DEPS_DIR}/libssh2-project"
        DEPENDS openssl_android
        CMAKE_ARGS
            -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}
            -DANDROID_ABI=${ANDROID_ABI}
            -DANDROID_PLATFORM=${ANDROID_PLATFORM}
            -DANDROID_STL=${ANDROID_STL}
            -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
            -DCMAKE_INSTALL_PREFIX=${LIBSSH2_INSTALL_DIR}
            -DCMAKE_INSTALL_LIBDIR=lib
            -DBUILD_EXAMPLES=OFF
            -DBUILD_TESTING=OFF
            -DBUILD_SHARED_LIBS=OFF
            -DBUILD_STATIC_LIBS=ON
            -DCMAKE_POSITION_INDEPENDENT_CODE=ON
            -DENABLE_ZLIB_COMPRESSION=ON
            -DCRYPTO_BACKEND=OpenSSL
            -DOPENSSL_ROOT_DIR=${OPENSSL_INSTALL_DIR}
            -DOPENSSL_INCLUDE_DIR=${OPENSSL_INCLUDE_DIR}
            -DOPENSSL_SSL_LIBRARY=${OPENSSL_SSL_LIBRARY}
            -DOPENSSL_CRYPTO_LIBRARY=${OPENSSL_CRYPTO_LIBRARY}
        BUILD_BYPRODUCTS "${LIBSSH2_LIBRARY}"
)

add_library(OpenSSL::Crypto STATIC IMPORTED GLOBAL)
set_target_properties(OpenSSL::Crypto PROPERTIES
        IMPORTED_LOCATION "${OPENSSL_CRYPTO_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${OPENSSL_INCLUDE_DIR}"
)
add_dependencies(OpenSSL::Crypto openssl_android)

add_library(libssh2_android STATIC IMPORTED GLOBAL)
set_target_properties(libssh2_android PROPERTIES
        IMPORTED_LOCATION "${LIBSSH2_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${LIBSSH2_INCLUDE_DIR}"
        INTERFACE_LINK_LIBRARIES OpenSSL::Crypto
)
add_dependencies(libssh2_android libssh2_android_project)

# hev-socks5-tunnel sources (local copy)
set(HEV_DIR ${CMAKE_CURRENT_SOURCE_DIR}/hev-socks5-tunnel)

# Main hev-socks5-tunnel sources (Linux only)
file(GLOB_RECURSE HEV_TUNNEL_SOURCES
        "${HEV_DIR}/src/*.c"
)
list(FILTER HEV_TUNNEL_SOURCES EXCLUDE REGEX
        "/hev-tunnel-freebsd\\.c$|/hev-tunnel-macos\\.c$|/hev-tunnel-netbsd\\.c$|/hev-tunnel-windows\\.c$"
)
list(FILTER HEV_TUNNEL_SOURCES EXCLUDE REGEX
        "/hev-jni\\.c$"
)
list(FILTER HEV_TUNNEL_SOURCES EXCLUDE REGEX
        "/hev-list\\.c$"
)
list(FILTER HEV_TUNNEL_SOURCES EXCLUDE REGEX
        "/src/core/"
)

# hev-socks5-core sources
file(GLOB HEV_CORE_SOURCES "${HEV_DIR}/src/core/src/*.c")
list(FILTER HEV_CORE_SOURCES EXCLUDE REGEX
        "/hev-rbtree\\.c$"
)

# yaml sources
file(GLOB YAML_SOURCES "${HEV_DIR}/third-part/yaml/src/*.c")

# lwip sources
file(GLOB_RECURSE LWIP_SOURCES "${HEV_DIR}/third-part/lwip/src/core/*.c")
file(GLOB LWIP_PORT_MEM "${HEV_DIR}/third-part/lwip/src/ports/lib/*.c")
list(APPEND LWIP_SOURCES ${LWIP_PORT_MEM})

# hev-task-system sources (Linux/epoll only)
file(GLOB_RECURSE HEV_TASK_SOURCES "${HEV_DIR}/third-part/hev-task-system/src/*.c")
list(FILTER HEV_TASK_SOURCES EXCLUDE REGEX
        "/hev-task-io-reactor-kqueue\\.c$|/hev-task-io-reactor-iocp\\.c$"
)

# hev-task-system arch-specific assembly (preprocessed .S includes arch .s)
set(HEV_TASK_ASM "${HEV_DIR}/third-part/hev-task-system/src/kern/task/hev-task-execute.S")

add_library(${CMAKE_PROJECT_NAME} SHARED
        sshproxy_jni.cpp
        hev-compat.c
        ${PROXY_OVER_SSH_DIR}/SSHProxy.cpp
        ${PROXY_OVER_SSH_DIR}/SshSocket.cpp
        ${PROXY_OVER_SSH_DIR}/SshSessionHandler.cpp
        ${PROXY_OVER_SSH_DIR}/SshHostKey.cpp
        ${PROXY_OVER_SSH_DIR}/HttpConnect.cpp
        ${PROXY_OVER_SSH_DIR}/SessionPool.cpp
        ${HEV_TUNNEL_SOURCES}
        ${HEV_CORE_SOURCES}
        ${YAML_SOURCES}
        ${LWIP_SOURCES}
        ${HEV_TASK_SOURCES}
        ${HEV_TASK_ASM}
)

target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
        ${PROXY_OVER_SSH_DIR}
        ${HEV_DIR}/src
        ${HEV_DIR}/src/misc
        ${HEV_DIR}/src/core/include
        ${HEV_DIR}/src/core/src
        ${HEV_DIR}/third-part/yaml/include
        ${HEV_DIR}/third-part/yaml/src
        ${HEV_DIR}/third-part/lwip/src/include
        ${HEV_DIR}/third-part/lwip/src/ports/include
        ${HEV_DIR}/third-part/hev-task-system/include
        ${HEV_DIR}/third-part/hev-task-system/src
        ${HEV_DIR}/third-part/hev-task-system/src/kern/task
)

target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE
        ENABLE_LIBRARY
        COMMIT_ID=\"android\"
        FD_SET_DEFINED
        YAML_VERSION_MAJOR=0
        YAML_VERSION_MINOR=2
        YAML_VERSION_PATCH=5
        YAML_VERSION_STRING=\"0.2.5\"
        CONFIG_STACK_BACKEND=STACK_MMAP
        CONFIG_STACK_OVERFLOW_DETECTION=1
        CONFIG_MEMALLOC_SLICE_ALIGN=64
        CONFIG_MEMALLOC_SLICE_MAX_SIZE=4096
        CONFIG_MEMALLOC_SLICE_MAX_COUNT=1000
        CONFIG_SCHED_CLOCK=CLOCK_NONE
        ENABLE_STACK_OVERFLOW_DETECTION
        ENABLE_MEMALLOC_SLICE
        ENABLE_IO_SPLICE_SYSCALL
)

target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE
        CoroLite::coro_lite
        OpenSSL::Crypto
        libssh2_android
        dl z log android
)
add_dependencies(${CMAKE_PROJECT_NAME} libssh2_android_project)

target_compile_options(${CMAKE_PROJECT_NAME} PRIVATE
        -Wall -Wextra -Wno-unused-variable -Wno-unused-parameter -Wno-unused-private-field
        -fno-omit-frame-pointer
)
