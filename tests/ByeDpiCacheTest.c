#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "mpool.h"

int main(void)
{
    struct desync_params group = {0};
    struct mphdr *const cache = mem_pool(MF_EXTRA, CMP_BITS);
    FILE *const input = tmpfile();
    assert(cache && input);
    fputs("0 127.0.0.1 -100 22 1 -\n"
          "0 127.0.0.2 -100 22 1 -\n"
          "0 127.0.0.1 -1 22 1 -\n"
          "0 127.0.0.1 33 22 1 -\n"
          "0 ::1 129 22 1 -\n"
          "0 127.0.0.1 2147483647 22 1 -\n"
          "0 127.0.0.1 9999999999999999999999999999999999999999 22 1 -\n"
          "0\n\n", input);
    for (int i = 0; i < 2048; ++i) fputc('x', input);
    fputs("\n0 127.0.0.1 0 20 1 -\n"
          "0 127.0.0.1 32 21 1 -\n"
          "0 ::1 0 22 1 -\n"
          "0 ::1 128 23 1 -\n"
          "0 127.1.0.1 16 24 1 old.example\n"
          "0 127.1.0.1 16 24 1 new.example", input);
    rewind(input);
    load_cache(cache, input, &group);
    fclose(input);
    assert(cache->count == 5);

    struct cache_key key = {0};
    key.family = AF_INET;
    key.port = htons(24);
    assert(inet_pton(AF_INET, "127.1.0.1", &key.ip.v4) == 1);
    const struct elem_i *const entry = mem_get(cache, (char *)&key, (int)offsetof(struct cache_key, ip.v4) * 8 + 16);
    assert(entry && entry->extra && !strcmp(entry->extra, "new.example"));

    FILE *const output = tmpfile();
    assert(output);
    dump_cache(cache, output, &group);
    rewind(output);
    struct mphdr *const restored = mem_pool(MF_EXTRA, CMP_BITS);
    assert(restored);
    load_cache(restored, output, &group);
    assert(restored->count == cache->count);
    fclose(output);
    mem_destroy(restored);
    mem_destroy(cache);
    return 0;
}
