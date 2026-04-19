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
#include "CancellationToken.h"

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
            return "-----BEGIN OPENSSH PRIVATE KEY-----\n" + key +
                   "\n-----END OPENSSH PRIVATE KEY-----";
        }
        return key;
    }

    JavaVM *gJvm = nullptr;
    jobject gListener = nullptr;

    jmethodID gMethodOnStarted = nullptr;
    jmethodID gMethodOnFinished = nullptr;
    jmethodID gMethodOnError = nullptr;

    struct ProxyContext {
        CancellationTokenSource cancellationTokenSource;
        std::shared_ptr<SessionPool> sessionPool;
        std::unique_ptr<SSHProxy> proxy;
        std::thread tunnelThread;

        ProxyContext()
                : sessionPool(std::make_shared<SessionPool>()),
                  proxy(std::make_unique<SSHProxy>(cancellationTokenSource)) {
        }
    };

    void CallVoidMethodOnListener(jmethodID method) {
        if (!gJvm || !gListener || !method) {
            return;
        }

        JNIEnv *env = nullptr;
        bool needDetach = false;

        jint result = gJvm->GetEnv((void **) &env, JNI_VERSION_1_6);
        if (result == JNI_EDETACHED) {
            if (gJvm->AttachCurrentThread(&env, nullptr) != JNI_OK) {
                return;
            }
            needDetach = true;
        }

        env->CallVoidMethod(gListener, method);

        if (needDetach) {
            gJvm->DetachCurrentThread();
        }
    }

    void CallErrorMethodOnListener(long code, const char *message) {
        if (!gJvm || !gListener || !gMethodOnError) {
            return;
        }

        JNIEnv *env = nullptr;
        bool needDetach = false;

        if (gJvm->GetEnv((void **) &env, JNI_VERSION_1_6) == JNI_EDETACHED) {
            if (gJvm->AttachCurrentThread(&env, nullptr) != JNI_OK) return;
            needDetach = true;
        }

        jstring jmsg = env->NewStringUTF(message);
        env->CallVoidMethod(gListener, gMethodOnError, static_cast<jlong>(code), jmsg);
        env->DeleteLocalRef(jmsg);

        if (needDetach) {
            gJvm->DetachCurrentThread();
        }
    }

    void onProxyStarted() {
        CallVoidMethodOnListener(gMethodOnStarted);
    }

    void onProxyFinished() {
        CallVoidMethodOnListener(gMethodOnFinished);
    }

} // namespace


extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    gJvm = vm;
    JNIEnv *env = nullptr;
    if (vm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    jclass listenerClass = env->FindClass("io/sshproxy/app/ProxyListener");
    if (listenerClass == nullptr) {
        return JNI_ERR;
    }

    gMethodOnStarted = env->GetMethodID(listenerClass, "onStarted", "()V");
    gMethodOnFinished = env->GetMethodID(listenerClass, "onFinished", "()V");
    gMethodOnError = env->GetMethodID(listenerClass, "onError", "(JLjava/lang/String;)V");

    env->DeleteLocalRef(listenerClass);

    return JNI_VERSION_1_6;
}

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
    const char *keyStr =
            privateKeyData != nullptr ? env->GetStringUTFChars(privateKeyData, nullptr) : nullptr;

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
        const auto factory = [sshConfig, sessionPool = ctx->sessionPool](
                const Endpoint &) -> BackendSocketPtr {
            return std::make_shared<SshSocket>(sshConfig, sessionPool);
        };
        ProxyConfig proxyConfig{
                .backendFactory = factory,
                .listenPort = static_cast<uint16_t>(listenPort),
        };
        ctx->proxy->start(proxyConfig,
                          onProxyStarted,
                          onProxyFinished);
    } catch (const std::exception &e) {
        env->ThrowNew(env->FindClass("java/lang/RuntimeException"), e.what());
    }
}

extern "C" JNIEXPORT void JNICALL
Java_io_sshproxy_app_ProxyNative_nativeStop(JNIEnv *env, jobject /*thiz*/, jlong handle) {
    if (handle == 0) {
        return;
    }
    reinterpret_cast<ProxyContext *>(handle)->cancellationTokenSource.requestStop();
}

extern "C" JNIEXPORT void JNICALL
Java_io_sshproxy_app_ProxyNative_nativeDestroy(JNIEnv *env, jobject /*thiz*/, jlong handle) {
    if (handle == 0) {
        return;
    }
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
    if (handle == 0) {
        return;
    }
    auto *ctx = reinterpret_cast<ProxyContext *>(handle);
    if (ctx->tunnelThread.joinable()) {
        hev_socks5_tunnel_quit();
        ctx->tunnelThread.join();
    }
}

extern "C"
JNIEXPORT void JNICALL
Java_io_sshproxy_app_ProxyNative_registerListener(JNIEnv *env, jobject thiz, jobject listener) {
    if (gListener != nullptr) {
        env->DeleteGlobalRef(gListener);
    }
    gListener = env->NewGlobalRef(listener);
}

extern "C"
JNIEXPORT void JNICALL
Java_io_sshproxy_app_ProxyNative_unregisterListener(JNIEnv *env, jobject thiz) {
    if (gListener != nullptr) {
        env->DeleteGlobalRef(gListener);
        gListener = nullptr;
    }
}
