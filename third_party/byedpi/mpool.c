#include "mpool.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>


static int bit_cmp(const struct elem *p, const struct elem *q)
{
    int len = q->len < p->len ? q->len : p->len;
    int df = len % 8, bytes = len / 8;
    int cmp = memcmp(p->data, q->data, bytes);
    
    if (cmp || !df) {
        return cmp;
    }
    uint8_t c1 = p->data[bytes] >> (8 - df);
    uint8_t c2 = q->data[bytes] >> (8 - df);
    if (c1 != c2) {
        if (c1 < c2) return -1;
        else return 1;
    }
    return 0;
}


static int byte_cmp(const struct elem *p, const struct elem *q)
{
    if (p->len != q->len) {
        return p->len < q->len ? -1 : 1;
    }
    return memcmp(p->data, q->data, p->len);
}


static int host_cmp(const struct elem *p, const struct elem *q)
{
    int len = q->len < p->len ? q->len : p->len;
    char *pd = p->data + p->len, *qd = q->data + q->len;
    
    while (len-- > 0) {
        if (*--pd != *--qd) {
            return *pd < *qd ? -1 : 1;
        }
    }
    if (p->len == q->len 
            || (p->len > q->len ? pd[-1] : qd[-1]) == '.')
        return 0;
    
    return p->len > q->len ? 1 : -1;
}


static int scmp(const struct elem *p, const struct elem *q)
{
    switch (p->cmp_type) {
    case CMP_BITS:
        return bit_cmp(p, q);
    case CMP_HOST:
        return host_cmp(p, q);
    default:
        return byte_cmp(p, q);
    }
}

KAVL_INIT(my, struct elem, head, scmp)


struct mphdr *mem_pool(unsigned short flags, unsigned char cmp_type)
{
    struct mphdr *hdr = calloc(1, sizeof(struct mphdr));
    if (hdr) {
        hdr->flags = flags;
        hdr->cmp_type = cmp_type;
    }
    return hdr;
}


void *mem_get(const struct mphdr *hdr, const char *str, int len)
{
    struct elem temp = { 
        .cmp_type = hdr->cmp_type,
        .len = len, .data = (char *)str 
    };
    return kavl_find(my, hdr->root, &temp, 0);
}


static void destroy_elem(struct mphdr *hdr, struct elem *e)
{
    if (!(hdr->flags & MF_STATIC)) {
        free(e->data);
    }
    if (hdr->flags & MF_EXTRA) {
        free(((struct elem_ex *)e)->extra);
    }
    free(e);
}


void *mem_add(struct mphdr *hdr, char *str, int len, size_t struct_size)
{
    struct elem *v, *e = calloc(1, struct_size);
    if (!e) {
        return 0;
    }
    e->len = len;
    e->cmp_type = hdr->cmp_type;
    e->data = str;
    
    v = kavl_insert(my, &hdr->root, e, 0);
    while (e != v && e->len < v->len) {
        mem_delete(hdr, v->data, v->len);
        v = kavl_insert(my, &hdr->root, e, 0);
    }
    if (e != v) {
        destroy_elem(hdr, e);
    }
    else hdr->count++;
    return v;
}


void mem_delete(struct mphdr *hdr, const char *str, int len)
{
    struct elem temp = { 
        .cmp_type = hdr->cmp_type,
        .len = len, .data = (char *)str 
    };
    struct elem *e = kavl_erase(my, &hdr->root, &temp, 0);
    if (!e) {
        return;
    }
    destroy_elem(hdr, e);
    hdr->count--;
}


void mem_destroy(struct mphdr *hdr)
{
    while (hdr && hdr->root) {
        struct elem *e = kavl_erase_first(my, &hdr->root);
        if (!e) {
            break;
        }
        destroy_elem(hdr, e);
    }
    free(hdr);
}


void dump_cache(struct mphdr *hdr, FILE *out, struct desync_params *dp)
{
    if (!hdr->root) {
        return;
    }
    kavl_itr_t(my) itr;
    kavl_itr_first(my, hdr->root, &itr);
    do {
        struct elem_i *p = (struct elem_i *)kavl_at(&itr);
        struct cache_key *key = (struct cache_key *)p->main.data;
        
        if (p->dp != dp) {
            continue;
        }
        char ADDR_STR[INET6_ADDRSTRLEN];
        if (key->family == AF_INET)
            inet_ntop(AF_INET, &key->ip.v4, ADDR_STR, sizeof(ADDR_STR));
        else
            inet_ntop(AF_INET6, &key->ip.v6, ADDR_STR, sizeof(ADDR_STR));
        
        int bitlen = p->main.len - offsetof(struct cache_key, ip.v4) * 8;
        fprintf(out, "0 %s %d %d %jd %.*s\n", 
            ADDR_STR, bitlen, ntohs(key->port),
            (intmax_t)p->time, p->extra_len ? p->extra_len : 1, p->extra ? p->extra : "-");
    } 
    while (kavl_itr_next(my, &itr));
    fflush(out);
}


static bool cache_number(char *text, intmax_t *value)
{
    char *end;
    errno = 0;
    *value = strtoimax(text, &end, 10);
    return !errno && end != text && !*end;
}

void load_cache(struct mphdr *hdr, FILE *in, struct desync_params *dp)
{
    char line[1024];
    while (fgets(line, sizeof(line), in)) {
        if (!strchr(line, '\n') && !feof(in)) {
            int ch;
            while ((ch = fgetc(in)) != '\n' && ch != EOF) {}
            continue;
        }
        char addr_str[INET6_ADDRSTRLEN], host[256];
        char prefix_text[64], port_text[64], time_text[64], trailing;
        if (sscanf(line, " 0 %45s %63s %63s %63s %255s %c",
                addr_str, prefix_text, port_text, time_text, host, &trailing) != 5) {
            continue;
        }
        intmax_t prefix, port, cache_time;
        if (!cache_number(prefix_text, &prefix) || !cache_number(port_text, &port)
                || !cache_number(time_text, &cache_time) || port < 0 || port > UINT16_MAX
                || (time_t)cache_time != cache_time) {
            continue;
        }
        struct cache_key key = { 0 };
        int key_size = offsetof(struct cache_key, ip.v4);
        
        if (inet_pton(AF_INET, addr_str, &key.ip.v4) <= 0) {
            if (inet_pton(AF_INET6, addr_str, &key.ip.v6) <= 0) {
                continue;
            } else {
                key.family = AF_INET6;
                key_size += sizeof(key.ip.v6);
            }
        }
        else {
            key.family = AF_INET;
            key_size += sizeof(key.ip.v4);
        }
        int address_bits = key.family == AF_INET ? 32 : 128;
        if (prefix < 0 || prefix > address_bits) {
            continue;
        }
        int bitlen = (int)prefix + (int)offsetof(struct cache_key, ip.v4) * 8;
        key.port = htons((uint16_t)port);
        
        struct cache_key *data = calloc(1, key_size);
        if (!data) {
            return;
        }
        memcpy(data, &key, key_size);
        size_t host_len = strlen(host);
        char *extra = host_len > 1 ? malloc(host_len + 1) : NULL;
        if (host_len > 1 && !extra) {
            free(data);
            return;
        }
        if (extra) memcpy(extra, host, host_len + 1);
        struct elem_i *e = mem_add(hdr, (char *)data, bitlen, sizeof(struct elem_i));
        if (!e) {
            free(data);
            free(extra);
            return;
        }
        e->time = (time_t)cache_time;
        e->extra_len = host_len;
        e->dp = dp;
        free(e->extra);
        e->extra = extra;
    }
}

