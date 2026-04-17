#include <jni.h>
#include <atomic>
#include <memory>
#include <string>
#include <algorithm>
#include <thread>

#include "SSHProxy.h"
#include "SshSocket.h"
#include "SessionPool.h"
#include "Logger.h"

extern "C" {
#include "hev-main.h"
}

namespace {
    std::string normalizeKeyData(std::string key) {
        size_t pos = 0;
        while ((pos = key.find("\\n", pos)) != std::string::npos) {
            key.replace(pos, 2, "\n");
            pos += 1;
        }
        if (key.find("-----BEGIN") == std::string::npos) {
            return "-----BEGIN OPENSSH PRIVATE KEY-----\n" + key + "\n-----END OPENSSH PRIVATE KEY-----";
        }
        return key;
    }
}

struct ProxyContext {
    std::atomic_bool stopFlag{false};
    std::shared_ptr<SessionPool> sessionPool;
    std::unique_ptr<SSHProxy> proxy;
    std::thread tunnelThread;

    ProxyContext()
        : sessionPool(std::make_shared<SessionPool>()),
          proxy(std::make_unique<SSHProxy>(stopFlag)) {
    }
};

extern "C" JNIEXPORT jlong JNICALL
Java_io_sshproxy_app_ProxyNative_nativeCreate(JNIEnv *env, jobject /*thiz*/) {
    try {
        auto *ctx = new ProxyContext();
        return reinterpret_cast<jlong>(ctx);
    } catch (const std::exception &e) {
        env->ThrowNew(env->FindClass("java/lang/RuntimeException"), e.what());
        return 0;
    }
}

extern "C" JNIEXPORT void JNICALL
Java_io_sshproxy_app_ProxyNative_nativeStart(JNIEnv *env, jobject /*thiz*/,
                                                   jlong handle,
                                                   jstring sshHost,
                                                   jint sshPort,
                                                   jstring sshUsername,
                                                   jstring privateKeyData,
                                                   jint listenPort) {
    if (handle == 0) {
        env->ThrowNew(env->FindClass("java/lang/IllegalArgumentException"), "Invalid handle");
        return;
    }

    auto *ctx = reinterpret_cast<ProxyContext *>(handle);

    const char *hostStr = env->GetStringUTFChars(sshHost, nullptr);
    const char *userStr = env->GetStringUTFChars(sshUsername, nullptr);
    const char *keyStr = privateKeyData != nullptr ? env->GetStringUTFChars(privateKeyData, nullptr) : nullptr;

    SSHConfig sshConfig;
    sshConfig.host = hostStr;
    sshConfig.port = static_cast<uint16_t>(sshPort);
    sshConfig.username = userStr;
    if (keyStr != nullptr) {
        sshConfig.privateKeyData = normalizeKeyData(std::string(keyStr));
    }


    env->ReleaseStringUTFChars(sshHost, hostStr);
    env->ReleaseStringUTFChars(sshUsername, userStr);
    if (keyStr != nullptr) {
        env->ReleaseStringUTFChars(privateKeyData, keyStr);
    }

    try {
        const auto factory = [sshConfig, sessionPool = ctx->sessionPool](const Endpoint &) -> BackendSocketPtr {
            return std::make_shared<SshSocket>(sshConfig, sessionPool);
        };
        ProxyConfig proxyConfig{
            .backendFactory = factory,
            .listenPort = static_cast<uint16_t>(listenPort),
        };
        ctx->proxy->start(proxyConfig);
    } catch (const std::exception &e) {
        env->ThrowNew(env->FindClass("java/lang/RuntimeException"), e.what());
    }
}

extern "C" JNIEXPORT void JNICALL
Java_io_sshproxy_app_ProxyNative_nativeStop(JNIEnv *env, jobject /*thiz*/, jlong handle) {
    if (handle == 0) return;
    reinterpret_cast<ProxyContext *>(handle)->proxy->requestStop();
}

extern "C" JNIEXPORT void JNICALL
Java_io_sshproxy_app_ProxyNative_nativeDestroy(JNIEnv *env, jobject /*thiz*/, jlong handle) {
    if (handle == 0) return;
    auto *ctx = reinterpret_cast<ProxyContext *>(handle);
    ctx->proxy->requestStop();
    ctx->proxy->waitForFinish();
    if (ctx->tunnelThread.joinable()) {
        hev_socks5_tunnel_quit();
        ctx->tunnelThread.join();
    }
    delete ctx;
}

extern "C" JNIEXPORT void JNICALL
Java_io_sshproxy_app_ProxyNative_nativeStartTunnel(JNIEnv *env, jobject /*thiz*/,
                                                         jlong handle,
                                                         jint tunFd,
                                                         jint socksPort) {
    if (handle == 0) {
        env->ThrowNew(env->FindClass("java/lang/IllegalArgumentException"), "Invalid handle");
        return;
    }

    auto *ctx = reinterpret_cast<ProxyContext *>(handle);

    if (ctx->tunnelThread.joinable()) {
        hev_socks5_tunnel_quit();
        ctx->tunnelThread.join();
    }

    std::string config = "tunnel:\n"
                         "  mtu: 1500\n"
                         "  ipv4: 10.0.0.2\n"
                         "  ipv6: 'fc00::1'\n"
                         "socks5:\n"
                         "  port: " + std::to_string(socksPort) + "\n"
                         "  address: 127.0.0.1\n"
                         "  udp: 'udp'\n";

    auto configStr = std::make_shared<std::string>(std::move(config));
    ctx->tunnelThread = std::thread([configStr, tunFd]() {
        hev_socks5_tunnel_main_from_str(
            reinterpret_cast<const unsigned char *>(configStr->data()),
            static_cast<unsigned int>(configStr->size()),
            tunFd
        );
    });
}

extern "C" JNIEXPORT void JNICALL
Java_io_sshproxy_app_ProxyNative_nativeStopTunnel(JNIEnv *env, jobject /*thiz*/, jlong handle) {
    if (handle == 0) return;
    auto *ctx = reinterpret_cast<ProxyContext *>(handle);
    if (ctx->tunnelThread.joinable()) {
        hev_socks5_tunnel_quit();
        ctx->tunnelThread.join();
    }
}
