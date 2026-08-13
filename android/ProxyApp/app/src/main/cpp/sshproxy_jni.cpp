#include <jni.h>

#include <cstdint>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>

#include "CancellationToken.h"
#include "Endpoint.h"
#include "Logger.h"
#include "SSHProxy.h"
#include "SessionPool.h"
#include "SshSocket.h"

extern "C" {
#include "hev-main.h"
}

using namespace CoroLite;

namespace {
    JavaVM *gJvm = nullptr;
    jmethodID gMethodOnStarted = nullptr;
    jmethodID gMethodOnFinished = nullptr;
    jmethodID gMethodOnError = nullptr;
    jmethodID gMethodOnTunnelFinished = nullptr;

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

    class UtfString final {
    public:
        UtfString(JNIEnv *env_, jstring value_, const char *name) : env(env_), value(value_) {
            if (value == nullptr) {
                throw std::invalid_argument(std::string(name) + " must not be null");
            }
            chars = env->GetStringUTFChars(value, nullptr);
            if (chars == nullptr) {
                throw std::runtime_error(std::string("Unable to read ") + name);
            }
        }

        UtfString(const UtfString &) = delete;
        UtfString &operator=(const UtfString &) = delete;

        ~UtfString() {
            if (chars != nullptr) {
                env->ReleaseStringUTFChars(value, chars);
            }
        }

        [[nodiscard]] std::string str() const {
            return chars;
        }

    private:
        JNIEnv *env;
        jstring value;
        const char *chars = nullptr;
    };

    struct ProxyContext final {
        CancellationTokenSource cancellationTokenSource;
        std::shared_ptr<SessionPool> sessionPool = std::make_shared<SessionPool>();
        std::unique_ptr<SSHProxy> proxy = std::make_unique<SSHProxy>(cancellationTokenSource);
        std::thread tunnelThread;
        std::mutex listenerMutex;
        jobject listener = nullptr;
    };

    class AttachedEnv final {
    public:
        AttachedEnv() {
            if (gJvm == nullptr) {
                return;
            }
            const jint result = gJvm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6);
            if (result == JNI_EDETACHED) {
                if (gJvm->AttachCurrentThread(&env, nullptr) == JNI_OK) {
                    detach = true;
                } else {
                    env = nullptr;
                }
            } else if (result != JNI_OK) {
                env = nullptr;
            }
        }

        AttachedEnv(const AttachedEnv &) = delete;
        AttachedEnv &operator=(const AttachedEnv &) = delete;

        ~AttachedEnv() {
            if (detach && gJvm != nullptr) {
                gJvm->DetachCurrentThread();
            }
        }

        [[nodiscard]] JNIEnv *get() const noexcept {
            return env;
        }

    private:
        JNIEnv *env = nullptr;
        bool detach = false;
    };

    jobject acquireListener(JNIEnv *env, ProxyContext *ctx) {
        std::lock_guard lock(ctx->listenerMutex);
        return ctx->listener == nullptr ? nullptr : env->NewLocalRef(ctx->listener);
    }

    void clearCallbackException(JNIEnv *env) {
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
            log_e("Java proxy callback threw an exception\n");
        }
    }

    void callVoidMethod(ProxyContext *ctx, const jmethodID method) {
        if (ctx == nullptr || method == nullptr) {
            return;
        }
        AttachedEnv attached;
        auto *const env = attached.get();
        if (env == nullptr) {
            return;
        }
        const auto listener = acquireListener(env, ctx);
        if (listener == nullptr) {
            return;
        }
        env->CallVoidMethod(listener, method);
        clearCallbackException(env);
        env->DeleteLocalRef(listener);
    }

    void callLongMethod(ProxyContext *ctx, const jmethodID method, const int64_t value) {
        if (ctx == nullptr || method == nullptr) {
            return;
        }
        AttachedEnv attached;
        auto *const env = attached.get();
        if (env == nullptr) {
            return;
        }
        const auto listener = acquireListener(env, ctx);
        if (listener == nullptr) {
            return;
        }
        env->CallVoidMethod(listener, method, static_cast<jlong>(value));
        clearCallbackException(env);
        env->DeleteLocalRef(listener);
    }

    void callErrorMethod(ProxyContext *ctx, const int64_t code, const std::string &message) {
        if (ctx == nullptr || gMethodOnError == nullptr) {
            return;
        }
        AttachedEnv attached;
        auto *const env = attached.get();
        if (env == nullptr) {
            return;
        }
        const auto listener = acquireListener(env, ctx);
        if (listener == nullptr) {
            return;
        }
        auto javaMessage = env->NewStringUTF(message.c_str());
        if (javaMessage != nullptr) {
            env->CallVoidMethod(listener, gMethodOnError, static_cast<jlong>(code), javaMessage);
            env->DeleteLocalRef(javaMessage);
        }
        clearCallbackException(env);
        env->DeleteLocalRef(listener);
    }

    void replaceListener(JNIEnv *env, ProxyContext *ctx, jobject listener) {
        const auto newListener = env->NewGlobalRef(listener);
        if (newListener == nullptr) {
            throw std::runtime_error("Unable to retain proxy listener");
        }
        jobject oldListener = nullptr;
        {
            std::lock_guard lock(ctx->listenerMutex);
            oldListener = std::exchange(ctx->listener, newListener);
        }
        if (oldListener != nullptr) {
            env->DeleteGlobalRef(oldListener);
        }
    }

    void deleteListener(JNIEnv *env, ProxyContext *ctx) noexcept {
        jobject listener = nullptr;
        {
            std::lock_guard lock(ctx->listenerMutex);
            listener = std::exchange(ctx->listener, nullptr);
        }
        if (listener != nullptr) {
            env->DeleteGlobalRef(listener);
        }
    }

    void throwJavaException(JNIEnv *env, const char *className, const std::string &message) noexcept {
        if (env->ExceptionCheck()) {
            return;
        }
        auto exceptionClass = env->FindClass(className);
        if (exceptionClass != nullptr) {
            env->ThrowNew(exceptionClass, message.c_str());
            env->DeleteLocalRef(exceptionClass);
        }
    }

    ProxyContext *requireContext(const jlong handle) {
        if (handle == 0) {
            throw std::invalid_argument("Invalid native proxy handle");
        }
        return reinterpret_cast<ProxyContext *>(handle);
    }

    uint16_t requirePort(const jint port, const char *name) {
        if (port < 1 || port > 65535) {
            throw std::invalid_argument(std::string(name) + " must be between 1 and 65535");
        }
        return static_cast<uint16_t>(port);
    }
} // namespace

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *) {
    gJvm = vm;
    JNIEnv *env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    jclass listenerClass = env->FindClass("io/sshproxy/app/ProxyListener");
    if (listenerClass == nullptr) {
        return JNI_ERR;
    }
    gMethodOnStarted = env->GetMethodID(listenerClass, "onStarted", "()V");
    gMethodOnFinished = env->GetMethodID(listenerClass, "onFinished", "()V");
    gMethodOnError = env->GetMethodID(listenerClass, "onError", "(JLjava/lang/String;)V");
    gMethodOnTunnelFinished = env->GetMethodID(listenerClass, "onTunnelFinished", "(J)V");
    const bool valid = gMethodOnStarted != nullptr && gMethodOnFinished != nullptr &&
                       gMethodOnError != nullptr && gMethodOnTunnelFinished != nullptr && !env->ExceptionCheck();
    env->DeleteLocalRef(listenerClass);
    return valid ? JNI_VERSION_1_6 : JNI_ERR;
}

extern "C" JNIEXPORT jlong JNICALL
Java_io_sshproxy_app_ProxyNative_nativeCreate(JNIEnv *env, jobject) {
    try {
        return reinterpret_cast<jlong>(new ProxyContext());
    } catch (const std::exception &e) {
        throwJavaException(env, "java/lang/RuntimeException", e.what());
        return 0;
    }
}

extern "C" JNIEXPORT void JNICALL
Java_io_sshproxy_app_ProxyNative_nativeRegisterListener(JNIEnv *env, jobject, const jlong handle, jobject listener) {
    try {
        if (listener == nullptr) {
            throw std::invalid_argument("Proxy listener must not be null");
        }
        replaceListener(env, requireContext(handle), listener);
    } catch (const std::exception &e) {
        throwJavaException(env, "java/lang/RuntimeException", e.what());
    }
}

extern "C" JNIEXPORT void JNICALL
Java_io_sshproxy_app_ProxyNative_nativeStart(JNIEnv *env,
                        jobject,
                        const jlong handle,
                        jstring sshHost,
                        const jint sshPort,
                        jstring sshUsername,
                        jstring privateKeyData,
                        jstring hostKeySha256,
                        const jint listenPort) {
    try {
        auto *const ctx = requireContext(handle);
        const UtfString host(env, sshHost, "SSH host");
        const UtfString username(env, sshUsername, "SSH username");
        const UtfString fingerprint(env, hostKeySha256, "SSH host-key fingerprint");

        SSHConfig sshConfig;
        sshConfig.host = host.str();
        sshConfig.port = requirePort(sshPort, "SSH port");
        sshConfig.username = username.str();
        sshConfig.hostKeySha256 = fingerprint.str();
        if (privateKeyData != nullptr) {
            const UtfString privateKey(env, privateKeyData, "SSH private key");
            sshConfig.privateKeyData = normalizeKeyData(privateKey.str());
        }

        const auto factory = [sshConfig, sessionPool = ctx->sessionPool](const Endpoint &) -> BackendSocketPtr {
            return std::make_shared<SshSocket>(sshConfig, sessionPool);
        };
        const ProxyConfig proxyConfig{
            .backendFactory = factory,
            .listenPort = requirePort(listenPort, "Proxy port"),
        };
        ctx->proxy->start(
            proxyConfig,
            [ctx] { callVoidMethod(ctx, gMethodOnStarted); },
            [ctx] { callVoidMethod(ctx, gMethodOnFinished); },
            [ctx](const int code, const std::string &message) { callErrorMethod(ctx, code, message); }
        );
    } catch (const std::exception &e) {
        throwJavaException(env, "java/lang/RuntimeException", e.what());
    }
}

extern "C" JNIEXPORT void JNICALL
Java_io_sshproxy_app_ProxyNative_nativeStop(JNIEnv *env, jobject, const jlong handle) {
    try {
        requireContext(handle)->proxy->requestStop();
    } catch (const std::exception &e) {
        throwJavaException(env, "java/lang/RuntimeException", e.what());
    }
}

extern "C" JNIEXPORT void JNICALL
Java_io_sshproxy_app_ProxyNative_nativeDestroy(JNIEnv *env, jobject, const jlong handle) {
    if (handle == 0) {
        return;
    }
    auto *const ctx = reinterpret_cast<ProxyContext *>(handle);
    try {
        ctx->proxy->requestStop();
        ctx->proxy->waitForFinish();
        if (ctx->tunnelThread.joinable()) {
            hev_socks5_tunnel_quit();
            ctx->tunnelThread.join();
        }
    } catch (const std::exception &e) {
        throwJavaException(env, "java/lang/RuntimeException", e.what());
    }
    deleteListener(env, ctx);
    delete ctx;
}

extern "C" JNIEXPORT void JNICALL
Java_io_sshproxy_app_ProxyNative_nativeStartTunnel(JNIEnv *env,
                                                   jobject,
                                                   const jlong handle,
                                                   const jint tunFd,
                                                   const jint socksPort) {
    try {
        auto *const ctx = requireContext(handle);
        requirePort(socksPort, "SOCKS port");
        if (tunFd < 0) {
            throw std::invalid_argument("Invalid VPN file descriptor");
        }
        if (ctx->tunnelThread.joinable()) {
            hev_socks5_tunnel_quit();
            ctx->tunnelThread.join();
        }

        auto config = std::make_shared<std::string>(
            "tunnel:\n"
            "  mtu: 1500\n"
            "  ipv4: 10.0.0.2\n"
            "  ipv6: 'fc00::1'\n"
            "socks5:\n"
            "  port: " + std::to_string(socksPort) + "\n"
            "  address: 127.0.0.1\n"
            "  udp: 'udp'\n"
        );
        ctx->tunnelThread = std::thread([ctx, config = std::move(config), tunFd] {
            const int result = hev_socks5_tunnel_main_from_str(
                reinterpret_cast<const unsigned char *>(config->data()),
                static_cast<unsigned int>(config->size()),
                tunFd
            );
            callLongMethod(ctx, gMethodOnTunnelFinished, result);
        });
    } catch (const std::exception &e) {
        throwJavaException(env, "java/lang/RuntimeException", e.what());
    }
}

extern "C" JNIEXPORT void JNICALL
Java_io_sshproxy_app_ProxyNative_nativeStopTunnel(JNIEnv *env, jobject, const jlong handle) {
    try {
        ProxyContext *const ctx = requireContext(handle);
        if (ctx->tunnelThread.joinable()) {
            hev_socks5_tunnel_quit();
            ctx->tunnelThread.join();
        }
    } catch (const std::exception &e) {
        throwJavaException(env, "java/lang/RuntimeException", e.what());
    }
}
