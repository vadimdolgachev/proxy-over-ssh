#include "Engine.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include "conev.h"
#include "error.h"
#include "params.h"
#include "proxy.h"

int parse_args(int argc, char **argv);
int get_default_ttl(void);
void clear_params(char *line, char **argv);
struct poolhd *byedpi_create_pool(int srvfd);

struct byedpi_engine {
    struct poolhd *pool;
    struct eval *stop_event;
    int stop_fd;
    uint16_t port;
};

static struct params defaults;
static int defaults_saved;
static byedpi_protect_fn protect_callback;
static void *protect_context;

int byedpi_protect_socket(const int fd) {
    if (protect_callback && protect_callback(fd, protect_context) != 0) {
        errno = EACCES;
        return -1;
    }
    return 0;
}

static void reset_params(void) {
    clear_params(NULL, NULL);
    free(params.need_free);
    params = defaults;
    protect_callback = NULL;
    protect_context = NULL;
}

static int on_stop(struct poolhd *pool, struct eval *value, const int events) {
    (void) events;
    value->mark = true;
    pool->brk = true;
    return 0;
}

struct byedpi_engine *byedpi_engine_create(const int argc, char **argv, const byedpi_protect_fn protect, void *context) {
    if (!defaults_saved) {
        defaults = params;
        defaults_saved = 1;
    }
    /* getopt state is process-global too. Never leave the host's parser changed. */
    const int saved_optind = optind, saved_opterr = opterr, saved_optopt = optopt;
    char *const saved_optarg = optarg;
    optind = 0;
    opterr = 0;
    const int result = parse_args(argc, argv);
    const int trailing_args = optind < argc;
    optind = saved_optind;
    opterr = saved_opterr;
    optopt = saved_optopt;
    optarg = saved_optarg;
    if (result || trailing_args || params.max_open > (INT_MAX - 2) / 2) {
        reset_params();
        return NULL;
    }
    if (!params.def_ttl && (params.def_ttl = get_default_ttl()) < 1) {
        reset_params();
        return NULL;
    }
    protect_callback = protect;
    protect_context = context;
    params.mode = MODE_SOCKS5;
    params.udp = false;
    params.resolve = false; /* SshSocket supplies the configured SSH IP address. */
    params.laddr = (union sockaddr_u) {.in = {
                                               .sin_family = AF_INET,
                                               .sin_addr = {.s_addr = htonl(INADDR_LOOPBACK)},
                                       }};
    struct byedpi_engine *const engine = calloc(1, sizeof(*engine));
    if (!engine) {
        reset_params();
        return NULL;
    }
    engine->stop_fd = -1;
    const int listener = listen_socket(&params.laddr);
    if (listener < 0)
        goto fail;
    struct sockaddr_in address;
    socklen_t length = sizeof(address);
    if (getsockname(listener, (struct sockaddr *) &address, &length) < 0) {
        close(listener);
        goto fail;
    }
    engine->port = ntohs(address.sin_port);
    engine->pool = byedpi_create_pool(listener); /* Takes ownership, also on failure. */
    if (!engine->pool)
        goto fail;
    engine->stop_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (engine->stop_fd < 0)
        goto fail;
    const int watch_fd = dup(engine->stop_fd);
    if (watch_fd < 0)
        goto fail;
    engine->stop_event = add_event(engine->pool, on_stop, watch_fd, POLLIN);
    if (!engine->stop_event) {
        close(watch_fd);
        goto fail;
    }
    return engine;
fail:
    byedpi_engine_destroy(engine);
    return NULL;
}

uint16_t byedpi_engine_port(const struct byedpi_engine *engine) {
    return engine->port;
}

static void save_caches(void) {
    for (struct desync_params *group = params.dp; group; group = group->next) {
        if (!group->cache_file) {
            continue;
        }
        const bool to_stdout = strcmp(group->cache_file, "-") == 0;
        FILE *const output = to_stdout ? stdout : fopen(group->cache_file, "w");
        if (!output) {
            uniperror("open cache for writing");
            continue;
        }
        dump_cache(params.mempool, output, group);
        if (ferror(output)) {
            uniperror("write cache");
        }
        if (!to_stdout && fclose(output)) {
            uniperror("close cache");
        }
    }
}

int byedpi_engine_run(struct byedpi_engine *engine) {
    loop_event(engine->pool);
    const int result = engine->pool->fatal_error ? -engine->pool->fatal_error : engine->stop_event->mark ? 0 : -EIO;
    /* Close the listener and all clients immediately, including on an unexpected exit. */
    destroy_pool(engine->pool);
    engine->pool = NULL;
    /* Only a started event loop may persist cache; failed initialization must not touch it. */
    save_caches();
    return result;
}

void byedpi_engine_request_stop(const struct byedpi_engine *engine) {
    const uint64_t value = 1;
    ssize_t result;
    do {
        result = write(engine->stop_fd, &value, sizeof(value));
    } while (result < 0 && errno == EINTR);
}

void byedpi_engine_destroy(struct byedpi_engine *engine) {
    if (!engine)
        return;
    if (engine->pool)
        destroy_pool(engine->pool);
    if (engine->stop_fd >= 0)
        close(engine->stop_fd);
    free(engine);
    reset_params();
}
