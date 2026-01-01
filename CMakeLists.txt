cmake_minimum_required(VERSION 4.1)
project(proxy_over_ssh)

set(CMAKE_CXX_STANDARD 23)

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
if(ANDROID)
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

message("ANDROID_ABI=${ANDROID_ABI}")
message("ANDROID_NDK=${ANDROID_NDK}")
message("ANDROID_NATIVE_API_LEVEL=${ANDROID_NATIVE_API_LEVEL}")
message("ANDROID_PLATFORM=${ANDROID_PLATFORM}")

add_executable(proxy_over_ssh main.cpp
        SSHProxy.cpp
        SSHProxy.h
)
target_link_libraries(proxy_over_ssh PRIVATE
        OpenSSL::Crypto
        OpenSSL::SSL
        libssh2
)

if(ANDROID)
    target_link_libraries(proxy_over_ssh PRIVATE dl z log android)
endif()