#ifndef BYEDPI_ENGINE_H
#define BYEDPI_ENGINE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct byedpi_engine;
typedef int (*byedpi_protect_fn)(int fd, void *context);
/* Called by the embedded socket adapter before connecting an outgoing socket. */
int byedpi_protect_socket(int fd);

/* Calls are serialized by ByeDpiRuntime; request_stop alone may run concurrently. */
struct byedpi_engine *byedpi_engine_create(int argc, char **argv, byedpi_protect_fn protect, void *context);
uint16_t byedpi_engine_port(const struct byedpi_engine *engine);
/* Returns zero on requested shutdown, otherwise a negative errno. */
int byedpi_engine_run(struct byedpi_engine *engine);
void byedpi_engine_request_stop(const struct byedpi_engine *engine);
void byedpi_engine_destroy(struct byedpi_engine *engine);

#ifdef __cplusplus
}
#endif

#endif // BYEDPI_ENGINE_H
