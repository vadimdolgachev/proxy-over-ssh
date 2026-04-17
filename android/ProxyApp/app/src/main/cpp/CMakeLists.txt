cmake_minimum_required(VERSION 3.22.1)
project(proxyapp LANGUAGES C CXX ASM)

set(CMAKE_CXX_STANDARD 23)

include(proxy-over-ssh/cmake/CPM.cmake)

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
set(OPENSSL_SSL_LIBRARY ${openssl-cmake_BINARY_DIR}/ssl/libssl_1_1.a)
set(OPENSSL_CRYPTO_LIBRARY ${openssl-cmake_BINARY_DIR}/crypto/libcrypto_1_1.a)

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
        proxy-over-ssh/SSHProxy.cpp
        proxy-over-ssh/Socket.cpp
        proxy-over-ssh/SshSocket.cpp
        proxy-over-ssh/SshSessionHandler.cpp
        proxy-over-ssh/Endpoint.cpp
        proxy-over-ssh/SessionPool.cpp
        ${HEV_TUNNEL_SOURCES}
        ${HEV_CORE_SOURCES}
        ${YAML_SOURCES}
        ${LWIP_SOURCES}
        ${HEV_TASK_SOURCES}
        ${HEV_TASK_ASM}
)

target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
        proxy-over-ssh
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
        OpenSSL::Crypto
        OpenSSL::SSL
        libssh2
        dl z log android
)

target_compile_options(${CMAKE_PROJECT_NAME} PRIVATE
        -Wall -Wextra -Wno-unused-variable -Wno-unused-parameter -Wno-unused-private-field
        -fno-omit-frame-pointer
)
