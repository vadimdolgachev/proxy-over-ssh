# Embedded ByeDPI

Source: https://github.com/hufrea/byedpi
Revision: `ba532298de7b28cfe854aea83d061369d13ca290` (17.3).
The upstream MIT license is retained in LICENSE.

Local changes:

- `main.c`: omit the executable entry point under `BYEDPI_EMBEDDED` and reject
  options controlling daemonization, PID files, listening, transparent mode,
  protection paths and upstream proxies. The host application owns these.
  Bound the number of groups before shifting and use a 64-bit group mask.
- `proxy.c`: expose pool creation separately from running the event loop and
  reserve one extra slot for the shutdown event.
- `extend.c`: call the host's socket protection callback before connecting and
  correct the format of the TLS record-size diagnostic.
- `mpool.c`: parse cache records line by line, validate numeric ranges before prefix
  arithmetic, and safely replace cached host names on duplicate records.
- `conev.c` / `conev.h`, `proxy.c`: retain fatal event-loop errno separately from requested shutdown.
- `error.h`: use the ByeDPI Android log tag, respect the configured debug level,
  and preserve errno while logging an error. Android builds enable ANDROID_APP.

The adapter in `byedpi/` uses the upstream argument parser and event loop,
without invoking upstream main(), init(), run() or installing signal handlers.
Only one embedded instance may run per process because upstream uses global state.
ByeDpiRuntime blocks SIGPIPE in its worker before starting the event loop, covering
send(), Android's fortified socket calls and splice(). The signal stays blocked
until that thread exits; the host's signal handler and calling-thread mask are unchanged.
The adapter implements cache writing and I/O diagnostics outside the vendored sources.
It saves configured caches once after an event loop exits, including fatal exits,
before releasing parser state. Initialization failures never rewrite caches. Cache I/O errors
are nonfatal and do not replace the event-loop failure code. Fatal exits notify the host so
it can stop the proxy; Android uses its existing error callback to close the proxy and VPN.
