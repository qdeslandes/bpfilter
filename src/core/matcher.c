/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "core/matcher.h"

#include <linux/in.h>

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/in6.h>
#include <linux/if_ether.h>

#include "core/dump.h"
#include "core/helper.h"
#include "core/logger.h"
#include "core/marsh.h"

#define BF_IPPROTO_MAX 256
#define BF_ETHERTYPE_MAX 65536

// c.f. https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
static const char *_bf_ethertype_strs[BF_ETHERTYPE_MAX] = {
    [ETH_P_IP] = "ipv4",
    [ETH_P_IPV6] = "ipv6",
};
static_assert(ARRAY_SIZE(_bf_ethertype_strs) == BF_ETHERTYPE_MAX,
              "missing entries in ethertype strings array");

const char *bf_ethertype_to_str(uint16_t proto)
{
    return _bf_ethertype_strs[proto];
}

int bf_ethertype_from_str(const char *str)
{
    bf_assert(str);

    for (int i = 0; i < BF_ETHERTYPE_MAX; ++i) {
        if (!_bf_ethertype_strs[i])
            continue;

        if (bf_streq(_bf_ethertype_strs[i], str))
            return i;
    }

    return -EINVAL;
}

int inet_pton(int af, const char * restrict src, void * restrict dst);
unsigned int if_nametoindex(const char *ifname);
char *if_indextoname(unsigned int ifindex, char *ifname);

static int _bf_parse_meta_ifindex(void *payload, char *str)
{
    long v;

    v = if_nametoindex(str);
    if (v != 0) {
        *(uint32_t *)payload = (uint32_t)v;
        return 0;
    }

    v = strtol(str, NULL, 10);
    if (0 <= v <= UINT32_MAX) {
        *(uint32_t *)payload = (uint32_t)v;
        return 0;
    }

    return bf_err_r(-EINVAL, "invalid ifindex '%s'", str);
}

#include <net/if.h>

static void _bf_print_meta_ifindex(const void *payload)
{
    char str[IF_NAMESIZE];

    if (if_indextoname(*(uint32_t *)payload, str))
        fprintf(stdout, "%s", str);
    else
        fprintf(stdout, "%d", *(uint32_t *)payload);
}

static int _bf_parse_meta_proba(void *payload, char *str)
{
    long v;

    v = strtol(str, NULL, 10);
    if (0 <= v <= 100) {
        *(uint8_t *)payload = (uint8_t)v;
        return 0;
    }

    return bf_err_r(-EINVAL, "invalid probability value '%s'", str);
}

static void _bf_print_meta_proba(const void *payload)
{
    fprintf(stdout, "%d%%", *(uint8_t *)payload);
}

static int _bf_parse_ip4_addr(void *payload, char *str)
{
    struct bf_matcher_ip4_addr *addr = payload;
    char *mask;
    long lmask;
    int r;

    addr->mask = 0xffffffff;

    mask = strchr(str, '/');
    if (mask) {
        *mask = '\0';
        ++mask;

        lmask = strtol(mask, NULL, 10);
        if (lmask < 0 && 32 < lmask)
            return bf_err_r(-ERANGE, "IPv4 address mask %s is invalid", mask);

        addr->mask <<= 32 - (uint32_t)lmask;
    }

    r = inet_pton(AF_INET, str, &addr->addr);
    if (r == 0)
        return bf_err_r(-EINVAL, "'%s' is not a valid IPv4 address", str);
    else if (r < 0)
        return bf_err_r(-ENOTSUP, "AF_INET is not a valid address family");

    return 0;
}

static void _bf_print_ip4_addr(const void *payload)
{
    const struct bf_matcher_ip4_addr *addr = payload;
    const uint8_t *ip = (uint8_t *)&addr->addr;

    fprintf(stdout, "%d.%d.%d.%d/%d", ip[0], ip[1], ip[2], ip[3],
            addr->mask ? 32 - __builtin_ctz(addr->mask) : 0);
}

static int _bf_parse_ip6_addr(void *payload, char *str)
{
    struct bf_matcher_ip6_addr *addr = payload;
    char *mask;
    long lmask = 128;
    int r;

    // If '/' is found, parse the mask, otherwise use /128.
    mask = strchr(str, '/');
    if (mask) {
        *mask = '\0';
        ++mask;

        lmask = strtol(mask, NULL, 10);
        if (lmask < 0 || lmask > 128)
            return bf_err_r(-ERANGE, "IPv6 address mask %s is invalid", mask);
    }

    for (int i = 0; i < lmask / 8; ++i)
        addr->mask[i] = (uint8_t)0xff;

    if (lmask % 8)
        addr->mask[lmask / 8] = (uint8_t)0xff << (8 - lmask % 8);

    r = inet_pton(AF_INET6, str, addr->addr);
    if (r == 0)
        return bf_err_r(-EINVAL, "'%s' is not a valid IPv6 address", str);
    else if (r < 0)
        return bf_err_r(-ENOTSUP, "AF_INET6 is not a valid address family");

    return 0;
}

#include <sys/socket.h>
#define INET6_ADDRSTRLEN 46
const char *inet_ntop(int af, const void * restrict src, char *dst,
                      socklen_t size);

static void _bf_print_ip6_addr(const void *payload)
{
    struct bf_matcher_ip6_addr *addr = payload;
    char str[INET6_ADDRSTRLEN];
    size_t prefix = 0;
    uint32_t *mask = (void *)addr->mask;

    for (int i = 0; i < 4 && mask[i]; ++i)
        prefix += 32 - __builtin_ctz(mask[i]);

    fprintf(stdout, "%s/%d",
            inet_ntop(AF_INET6, addr->addr, str, INET6_ADDRSTRLEN), prefix);
}

/**
 * @brief Array mapping IP protocol numbers to their string representation.
 *
 * See https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
 */
static const char *_bf_ipproto_strs[BF_IPPROTO_MAX] = {
    [IPPROTO_ICMP] = "icmp",
    [IPPROTO_IGMP] = "igmp",
    [IPPROTO_TCP] = "tcp",
    [IPPROTO_UDP] = "udp",
    [IPPROTO_ICMPV6] = "icmpv6"
};
static_assert(ARRAY_SIZE(_bf_ipproto_strs) == BF_IPPROTO_MAX,
              "IPPROTO_ strings array should contain BF_IPPROTO_MAX entries");

const char *bf_ipproto_to_str(uint8_t proto)
{
    return _bf_ipproto_strs[proto];
}

int bf_ipproto_from_str(const char *str, uint8_t *v)
{
    for (int i = 0; i < BF_IPPROTO_MAX; ++i) {
        if (bf_streq_i(_bf_ipproto_strs[i], str)) {
            *v = (uint8_t)i;
            return 0;
        }
    }

    return -EINVAL;
}

static int _bf_parse_u8(void *payload, char *str, struct bf_matcher_ops_parse_meta *meta)
{
    uint8_t v;
    char *endptr;
    int r;

    if (*str == '\0')
        return -EINVAL;

    if (meta) {
        r = meta->map_u8(str, &v);
        if (r >= 0) {
            *(uint8_t *)payload = v;
            return 0;
        }
    }

    r = strtol(str, &endptr, 0);
    if (!*endptr && 0 <= r && r <= UINT8_MAX) {
        *(uint8_t *)payload = (uint8_t)r;
        return 0;
    }

    return -EINVAL;
}

static void _bf_print_u8(const void *payload, struct bf_matcher_ops_print_meta *meta)
{
    const char *str;

    str = meta->map_u8(*(uint8_t *)payload);
    if (str)
        fprintf(stdout, "%s", str);
    else
        fprintf(stdout, "%d", *(uint8_t *)payload);
}

static int _bf_parse_ethertype(void *payload, char *str)
{
    uint16_t ethertype;
    int r;

    r = bf_ethertype_from_str(str);
    if (r >= 0) {
        *(uint16_t *)payload = (uint16_t)r;
        return 0;
    }

    r = strtol(str, NULL, 0);
    if (0 <= r && r <= 65535) {
        *(uint16_t *)payload = (uint16_t)r;
        return 0;
    }

    return bf_err_r(-EINVAL, "invalid ethertype number '%s'", str);
}

static void _bf_print_ethertype(const void *payload)
{
    const char *str;

    str = bf_ethertype_to_str(*(uint16_t *)payload);
    if (str)
        fprintf(stdout, "%s", str);
    else
        fprintf(stdout, "0x%04x", *(uint16_t *)payload);
}

static int _bf_parse_port(void *payload, char *str)
{
    long v;

    v = strtol(str, NULL, 0);
    if (0 <= v && v < USHRT_MAX) {
        *(uint16_t *)payload = (uint16_t)v;
        return 0;
    }

    return bf_err_r(-EINVAL, "invalid port value '%s'", str);
}

static void _bf_print_port(const void *payload)
{
    fprintf(stdout, "%u", *(uint16_t *)payload);
}

static int _bf_parse_port_range(void *payload, char *str)
{
    long v;
    uint16_t *ports = payload;
    char *next_port;
    int r;

    next_port = strchr(str, '-');
    if (!next_port)
        return bf_err_r(-EINVAL, "failed to find range delimiter in '%s'", str);

    *next_port = '\0';
    ++next_port;

    r = _bf_parse_port(&ports[0], str);
    if (r)
        return r;

    r = _bf_parse_port(&ports[1], next_port);
    if (r)
        return r;

    return 0;
}

static void _bf_print_port_range(const void *payload)
{
    uint16_t *ports = payload;

    fprintf(stdout, "%d-%d", ports[0], ports[1]);
}

static int _bf_parse_tcp_flags(void *payload, char *str)
{
    uint8_t flags = 0;
    char *flags_str;
    char *saveptr;
    char *token;
    int r;

    for (flags_str = str;; flags_str = NULL) {
        enum bf_matcher_tcp_flag flag;

        token = strtok_r(flags_str, ",", &saveptr);
        if (!token)
            break;

        r = bf_matcher_tcp_flag_from_str(token, &flag);
        if (r) {
            bf_err("unknown TCP flag '%s', ignoring\n", token);
            continue;
        }

        flags |= BF_FLAG(flag);
    }

    *(uint8_t *)payload = flags;

    return 0;
}

static void _bf_print_tcp_flags(const void *payload)
{
    size_t n = 0;

    for (int i = 0; i < 8; ++i) {
        if (*(uint8_t *)payload & (1 << i))
            ++n;
    }

    for (int i = 0; i < 8; ++i) {
        if ((1 << i) & *(uint8_t *)payload)
            fprintf(stdout, "%s%s", bf_matcher_tcp_flag_to_str(i),
                    n-- > 1 ? "," : "");
    }
}

#define BF_ICMP_TYPE_MAX 256
// c.f. https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml
// c.f. https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes#Icmp
static const char *_bf_icmp_type_strs[BF_ICMP_TYPE_MAX] = {
    [0] = "echo-reply",           [3] = "destination-unreachable",
    [4] = "source-quench",        [5] = "redirect",
    [6] = "echo-request",         [9] = "router-advertisement",
    [10] = "router-solicitation", [11] = "time-exceeded",
    [12] = "parameter-problem",   [13] = "timestamp-request",
    [14] = "timestamp-reply",     [15] = "info-request",
    [16] = "info-reply",          [17] = "address-mask-request",
    [18] = "address-mask-reply",
};
static_assert(ARRAY_SIZE(_bf_icmp_type_strs) == BF_ICMP_TYPE_MAX,
              "missing entries in ICMP type strings array");

const char *bf_icmp_type_to_str(uint16_t proto)
{
    return _bf_icmp_type_strs[proto];
}

int bf_icmp_type_from_str(const char *str)
{
    bf_assert(str);

    for (int i = 0; i < BF_ICMP_TYPE_MAX; ++i) {
        if (!_bf_icmp_type_strs[i])
            continue;

        if (bf_streq(_bf_icmp_type_strs[i], str))
            return i;
    }

    return -EINVAL;
}

static int _bf_parse_icmp_type(void *payload, char *str)
{
    uint8_t proto;
    int r;

    r = bf_icmp_type_from_str(str);
    if (r >= 0) {
        *(uint8_t *)payload = (uint8_t)r;
        return 0;
    }

    r = strtol(str, NULL, 0);
    if (0 <= r && r <= 255) {
        *(uint8_t *)payload = (uint8_t)r;
        return 0;
    }

    return bf_err_r(-EINVAL, "invalid ICMP type number '%s'", str);
}

static void _bf_print_icmp_type(const void *payload)
{
    const char *str;

    str = bf_icmp_type_to_str(*(uint8_t *)payload);
    if (str)
        fprintf(stdout, "%s", str);
    else
        fprintf(stdout, "%d", *(uint8_t *)payload);
}

static int _bf_parse_icmp_code(void *payload, char *str)
{
    long v;

    v = strtol(str, NULL, 0);
    if (0 <= v && v <= UCHAR_MAX) {
        *(uint8_t *)payload = (uint8_t)v;
        return 0;
    }

    return bf_err_r(-EINVAL, "invalid ICMP code value '%s'", str);
}

static void _bf_print_icmp_code(const void *payload)
{
    fprintf(stdout, "%d", *(uint8_t *)payload);
}

#define BF_ICMPV6_TYPE_MAX 256
// c.f. https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml
// c.f. https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes#Icmpv6
static const char *_bf_icmpv6_type_strs[BF_ICMPV6_TYPE_MAX] = {
    [1] = "destination-unreachable", [2] = "packet-too-big",
    [3] = "time-exceeded",           [4] = "parameter-problem",
    [128] = "echo-request",          [129] = "echo-reply",
    [130] = "mld-listener-query",    [131] = "mld-listener-report",
    [133] = "nd-router-solicit",     [134] = "nd-router-advert",
    [135] = "nd-neighbor-solicit",   [136] = "nd-neighbor-advert",
    [143] = "mld2-listener-report",
};

static_assert(ARRAY_SIZE(_bf_icmpv6_type_strs) == BF_ICMPV6_TYPE_MAX,
              "missing entries in ICMPv6 type strings array");

const char *bf_icmpv6_type_to_str(uint16_t proto)
{
    return _bf_icmpv6_type_strs[proto];
}

int bf_icmpv6_type_from_str(const char *str)
{
    bf_assert(str);

    for (int i = 0; i < BF_ICMPV6_TYPE_MAX; ++i) {
        if (!_bf_icmpv6_type_strs[i])
            continue;

        if (bf_streq(_bf_icmpv6_type_strs[i], str))
            return i;
    }

    return -EINVAL;
}

static int _bf_parse_icmpv6_type(void *payload, char *str)
{
    uint8_t proto;
    int r;

    r = bf_icmpv6_type_from_str(str);
    if (r >= 0) {
        *(uint8_t *)payload = (uint8_t)r;
        return 0;
    }

    r = strtol(str, NULL, 0);
    if (0 <= r && r <= 255) {
        *(uint8_t *)payload = (uint8_t)r;
        return 0;
    }

    return bf_err_r(-EINVAL, "invalid ICMPv6 type number '%s'", str);
}

static void _bf_print_icmpv6_type(const void *payload)
{
    const char *str;

    str = bf_icmpv6_type_to_str(*(uint8_t *)payload);
    if (str)
        fprintf(stdout, "%s", str);
    else
        fprintf(stdout, "%d", *(uint8_t *)payload);
}

static int _bf_parse_icmpv6_code(void *payload, char *str)
{
    long v;

    v = strtol(str, NULL, 0);
    if (0 <= v && v <= UCHAR_MAX) {
        *(uint8_t *)payload = (uint8_t)v;
        return 0;
    }

    return bf_err_r(-EINVAL, "invalid ICMPv6 code value '%s'", str);
}

static void _bf_print_icmpv6_code(const void *payload)
{
    fprintf(stdout, "%d", *(uint8_t *)payload);
}

#define BF_MATCHER_OPS(type, op, payload_size, parse, parse_meta, print, print_meta)                   \
    [type][op] = {payload_size, parse, parse_meta, print, print_meta}

static struct bf_matcher_ops
    _bf_matcher_ops[_BF_MATCHER_TYPE_MAX][_BF_MATCHER_OP_MAX] = {
        /* Meta matchers
        BF_MATCHER_OPS(BF_MATCHER_META_IFINDEX, BF_MATCHER_EQ, 4,
                       _bf_parse_meta_ifindex, _bf_print_meta_ifindex),
        BF_MATCHER_OPS(BF_MATCHER_META_L3_PROTO, BF_MATCHER_EQ, 2,
                       _bf_parse_ethertype, _bf_print_ethertype),
        BF_MATCHER_OPS(BF_MATCHER_META_L4_PROTO, BF_MATCHER_EQ, 1,
                       _bf_parse_ipproto, _bf_print_ipproto),
        BF_MATCHER_OPS(BF_MATCHER_META_SPORT, BF_MATCHER_EQ, 2, _bf_parse_port,
                       _bf_print_port),
        BF_MATCHER_OPS(BF_MATCHER_META_SPORT, BF_MATCHER_NE, 2, _bf_parse_port,
                       _bf_print_port),
        BF_MATCHER_OPS(BF_MATCHER_META_SPORT, BF_MATCHER_RANGE, 4,
                       _bf_parse_port_range, _bf_print_port_range),
        BF_MATCHER_OPS(BF_MATCHER_META_DPORT, BF_MATCHER_EQ, 2, _bf_parse_port,
                       _bf_print_port),
        BF_MATCHER_OPS(BF_MATCHER_META_DPORT, BF_MATCHER_NE, 2, _bf_parse_port,
                       _bf_print_port),
        BF_MATCHER_OPS(BF_MATCHER_META_DPORT, BF_MATCHER_RANGE, 4,
                       _bf_parse_port_range, _bf_print_port_range),
        BF_MATCHER_OPS(BF_MATCHER_META_PROBABILITY, BF_MATCHER_EQ, 2,
                       _bf_parse_meta_proba, _bf_print_meta_proba),

        /* IPv4 matchers
        BF_MATCHER_OPS(BF_MATCHER_IP4_SADDR, BF_MATCHER_EQ,
                       sizeof(struct bf_matcher_ip4_addr), _bf_parse_ip4_addr,
                       _bf_print_ip4_addr),
        BF_MATCHER_OPS(BF_MATCHER_IP4_SADDR, BF_MATCHER_NE,
                       sizeof(struct bf_matcher_ip4_addr), _bf_parse_ip4_addr,
                       _bf_print_ip4_addr),
        BF_MATCHER_OPS(BF_MATCHER_IP4_DADDR, BF_MATCHER_EQ,
                       sizeof(struct bf_matcher_ip4_addr), _bf_parse_ip4_addr,
                       _bf_print_ip4_addr),
        BF_MATCHER_OPS(BF_MATCHER_IP4_DADDR, BF_MATCHER_NE,
                       sizeof(struct bf_matcher_ip4_addr), _bf_parse_ip4_addr,
                       _bf_print_ip4_addr),*/
        BF_MATCHER_OPS(BF_MATCHER_IP4_PROTO, BF_MATCHER_EQ, 1,
                       _bf_parse_u8, {.map_u8 = bf_ipproto_from_str}, _bf_print_u8, {.map_u8 = bf_ipproto_to_str}),

        /* IPv6 matchers
        BF_MATCHER_OPS(BF_MATCHER_IP6_SADDR, BF_MATCHER_EQ,
                       sizeof(struct bf_matcher_ip6_addr), _bf_parse_ip6_addr,
                       _bf_print_ip6_addr),
        BF_MATCHER_OPS(BF_MATCHER_IP6_SADDR, BF_MATCHER_NE,
                       sizeof(struct bf_matcher_ip6_addr), _bf_parse_ip6_addr,
                       _bf_print_ip6_addr),
        BF_MATCHER_OPS(BF_MATCHER_IP6_DADDR, BF_MATCHER_EQ,
                       sizeof(struct bf_matcher_ip6_addr), _bf_parse_ip6_addr,
                       _bf_print_ip6_addr),
        BF_MATCHER_OPS(BF_MATCHER_IP6_DADDR, BF_MATCHER_NE,
                       sizeof(struct bf_matcher_ip6_addr), _bf_parse_ip6_addr,
                       _bf_print_ip6_addr),

        /* TCP matchers
        BF_MATCHER_OPS(BF_MATCHER_TCP_SPORT, BF_MATCHER_EQ, 2, _bf_parse_port,
                       _bf_print_port),
        BF_MATCHER_OPS(BF_MATCHER_TCP_SPORT, BF_MATCHER_NE, 2, _bf_parse_port,
                       _bf_print_port),
        BF_MATCHER_OPS(BF_MATCHER_TCP_SPORT, BF_MATCHER_RANGE, 4,
                       _bf_parse_port_range, _bf_print_port_range),
        BF_MATCHER_OPS(BF_MATCHER_TCP_DPORT, BF_MATCHER_EQ, 2, _bf_parse_port,
                       _bf_print_port),
        BF_MATCHER_OPS(BF_MATCHER_TCP_DPORT, BF_MATCHER_NE, 2, _bf_parse_port,
                       _bf_print_port),
        BF_MATCHER_OPS(BF_MATCHER_TCP_DPORT, BF_MATCHER_RANGE, 4,
                       _bf_parse_port_range, _bf_print_port_range),
        BF_MATCHER_OPS(BF_MATCHER_TCP_FLAGS, BF_MATCHER_EQ, 1,
                       _bf_parse_tcp_flags, _bf_print_tcp_flags),
        BF_MATCHER_OPS(BF_MATCHER_TCP_FLAGS, BF_MATCHER_NE, 1,
                       _bf_parse_tcp_flags, _bf_print_tcp_flags),
        BF_MATCHER_OPS(BF_MATCHER_TCP_FLAGS, BF_MATCHER_ANY, 1,
                       _bf_parse_tcp_flags, _bf_print_tcp_flags),
        BF_MATCHER_OPS(BF_MATCHER_TCP_FLAGS, BF_MATCHER_ALL, 1,
                       _bf_parse_tcp_flags, _bf_print_tcp_flags),

        /* UDP matchers
        BF_MATCHER_OPS(BF_MATCHER_UDP_SPORT, BF_MATCHER_EQ, 2, _bf_parse_port,
                       _bf_print_port),
        BF_MATCHER_OPS(BF_MATCHER_UDP_SPORT, BF_MATCHER_NE, 2, _bf_parse_port,
                       _bf_print_port),
        BF_MATCHER_OPS(BF_MATCHER_UDP_SPORT, BF_MATCHER_RANGE, 4,
                       _bf_parse_port_range, _bf_print_port_range),
        BF_MATCHER_OPS(BF_MATCHER_UDP_DPORT, BF_MATCHER_EQ, 2, _bf_parse_port,
                       _bf_print_port),
        BF_MATCHER_OPS(BF_MATCHER_UDP_DPORT, BF_MATCHER_NE, 2, _bf_parse_port,
                       _bf_print_port),
        BF_MATCHER_OPS(BF_MATCHER_UDP_DPORT, BF_MATCHER_RANGE, 4,
                       _bf_parse_port_range, _bf_print_port_range),

        /* ICMP matchers
        BF_MATCHER_OPS(BF_MATCHER_ICMP_TYPE, BF_MATCHER_EQ, 1,
                       _bf_parse_icmp_type, _bf_print_icmp_type),
        BF_MATCHER_OPS(BF_MATCHER_ICMP_TYPE, BF_MATCHER_NE, 1,
                       _bf_parse_icmp_type, _bf_print_icmp_type),
        BF_MATCHER_OPS(BF_MATCHER_ICMP_CODE, BF_MATCHER_EQ, 1,
                       _bf_parse_icmp_code, _bf_print_icmp_code),
        BF_MATCHER_OPS(BF_MATCHER_ICMP_CODE, BF_MATCHER_NE, 1,
                       _bf_parse_icmp_code, _bf_print_icmp_code),

        /* ICMPv6 matchers
        BF_MATCHER_OPS(BF_MATCHER_ICMPV6_TYPE, BF_MATCHER_EQ, 1,
                       _bf_parse_icmpv6_type, _bf_print_icmpv6_type),
        BF_MATCHER_OPS(BF_MATCHER_ICMPV6_TYPE, BF_MATCHER_NE, 1,
                       _bf_parse_icmpv6_type, _bf_print_icmpv6_type),
        BF_MATCHER_OPS(BF_MATCHER_ICMPV6_CODE, BF_MATCHER_EQ, 1,
                       _bf_parse_icmpv6_code, _bf_print_icmpv6_code),
        BF_MATCHER_OPS(BF_MATCHER_ICMPV6_CODE, BF_MATCHER_NE, 1,
                       _bf_parse_icmpv6_code, _bf_print_icmpv6_code),
                    */
};

struct bf_matcher_ops *bf_matcher_ops_get(enum bf_matcher_type type,
                                          enum bf_matcher_op op)
{
    return &_bf_matcher_ops[type][op];
}

int bf_matcher_new(struct bf_matcher **matcher, enum bf_matcher_type type,
                   enum bf_matcher_op op, const void *payload,
                   size_t payload_len)
{
    _free_bf_matcher_ struct bf_matcher *_matcher = NULL;

    bf_assert(matcher);
    bf_assert((payload && payload_len) || (!payload && !payload_len));

    _matcher = malloc(sizeof(struct bf_matcher) + payload_len);
    if (!_matcher)
        return -ENOMEM;

    _matcher->type = type;
    _matcher->op = op;
    _matcher->len = sizeof(struct bf_matcher) + payload_len;
    bf_memcpy(_matcher->payload, payload, payload_len);

    *matcher = TAKE_PTR(_matcher);

    return 0;
}

int bf_matcher_new_from_raw(struct bf_matcher **matcher,
                            enum bf_matcher_type type, enum bf_matcher_op op,
                            char *payload)
{
    _free_bf_matcher_ struct bf_matcher *_matcher = NULL;
    struct bf_matcher_ops *ops = bf_matcher_ops_get(type, op);
    const size_t total_len = sizeof(struct bf_matcher) + ops->payload_size;
    int r;

    if (!ops)
        return bf_err_r(-ENOENT, "no matcher_ops found for %d", type);

    _matcher = calloc(1, total_len);
    if (!_matcher)
        return -ENOMEM;

    _matcher->type = type;
    _matcher->op = op;
    _matcher->len = total_len;

    r = ops->parse(&_matcher->payload, payload, &ops->parse_meta);
    if (r) {
        return bf_err_r(r, "failed to parse payload '%s' for %s", payload,
                        bf_matcher_type_to_str(type));
    }

    *matcher = TAKE_PTR(_matcher);

    return 0;
}

int bf_matcher_new_from_marsh(struct bf_matcher **matcher,
                              const struct bf_marsh *marsh)
{
    struct bf_marsh *child = NULL;
    enum bf_matcher_type type;
    enum bf_matcher_op op;
    size_t payload_len;
    const void *payload;
    int r;

    bf_assert(matcher);
    bf_assert(marsh);

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    memcpy(&type, child->data, sizeof(type));

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    memcpy(&op, child->data, sizeof(op));

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    memcpy(&payload_len, child->data, sizeof(payload_len));
    payload_len -= sizeof(struct bf_matcher);

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    payload = child->data;

    r = bf_matcher_new(matcher, type, op, payload, payload_len);
    if (r)
        return bf_err_r(r, "failed to restore bf_matcher from serialised data");

    return 0;
}

void bf_matcher_free(struct bf_matcher **matcher)
{
    bf_assert(matcher);

    if (!*matcher)
        return;

    free(*matcher);
    *matcher = NULL;
}

int bf_matcher_marsh(const struct bf_matcher *matcher, struct bf_marsh **marsh)
{
    _free_bf_marsh_ struct bf_marsh *_marsh = NULL;
    int r;

    bf_assert(matcher);
    bf_assert(marsh);

    r = bf_marsh_new(&_marsh, NULL, 0);
    if (r < 0)
        return r;

    r |= bf_marsh_add_child_raw(&_marsh, &matcher->type, sizeof(matcher->type));
    r |= bf_marsh_add_child_raw(&_marsh, &matcher->op, sizeof(matcher->op));
    r |= bf_marsh_add_child_raw(&_marsh, &matcher->len, sizeof(matcher->len));
    r |= bf_marsh_add_child_raw(&_marsh, matcher->payload,
                                matcher->len - sizeof(struct bf_matcher));
    if (r)
        return bf_err_r(r, "failed to serialise bf_matcher object");

    *marsh = TAKE_PTR(_marsh);

    return 0;
}

void bf_matcher_dump(const struct bf_matcher *matcher, prefix_t *prefix)
{
    bf_assert(matcher);
    bf_assert(prefix);

    DUMP(prefix, "struct bf_matcher at %p", matcher);

    bf_dump_prefix_push(prefix);

    DUMP(prefix, "type: %s", bf_matcher_type_to_str(matcher->type));
    DUMP(prefix, "op: %s", bf_matcher_op_to_str(matcher->op));
    DUMP(prefix, "len: %ld", matcher->len);
    DUMP(bf_dump_prefix_last(prefix), "payload:");
    bf_dump_prefix_push(prefix);
    bf_dump_hex(prefix, matcher->payload,
                matcher->len - sizeof(struct bf_matcher));
    bf_dump_prefix_pop(prefix);

    bf_dump_prefix_pop(prefix);
}

static const char *_bf_matcher_type_strs[] = {
    [BF_MATCHER_META_IFINDEX] = "meta.ifindex",
    [BF_MATCHER_META_L3_PROTO] = "meta.l3_proto",
    [BF_MATCHER_META_L4_PROTO] = "meta.l4_proto",
    [BF_MATCHER_META_PROBABILITY] = "meta.probability",
    [BF_MATCHER_META_SPORT] = "meta.sport",
    [BF_MATCHER_META_DPORT] = "meta.dport",
    [BF_MATCHER_IP4_SADDR] = "ip4.saddr",
    [BF_MATCHER_IP4_SNET] = "ip4.snet",
    [BF_MATCHER_IP4_DADDR] = "ip4.daddr",
    [BF_MATCHER_IP4_DNET] = "ip4.dnet",
    [BF_MATCHER_IP4_PROTO] = "ip4.proto",
    [BF_MATCHER_IP6_SADDR] = "ip6.saddr",
    [BF_MATCHER_IP6_SNET] = "ip6.snet",
    [BF_MATCHER_IP6_DADDR] = "ip6.daddr",
    [BF_MATCHER_IP6_DNET] = "ip6.dnet",
    [BF_MATCHER_TCP_SPORT] = "tcp.sport",
    [BF_MATCHER_TCP_DPORT] = "tcp.dport",
    [BF_MATCHER_TCP_FLAGS] = "tcp.flags",
    [BF_MATCHER_UDP_SPORT] = "udp.sport",
    [BF_MATCHER_UDP_DPORT] = "udp.dport",
    [BF_MATCHER_SET_SRCIP6PORT] = "set.srcip6port",
    [BF_MATCHER_SET_SRCIP6] = "set.srcip6",
    [BF_MATCHER_ICMP_TYPE] = "icmp.type",
    [BF_MATCHER_ICMP_CODE] = "icmp.code",
    [BF_MATCHER_ICMPV6_TYPE] = "icmpv6.type",
    [BF_MATCHER_ICMPV6_CODE] = "icmpv6.code",
};

static_assert(ARRAY_SIZE(_bf_matcher_type_strs) == _BF_MATCHER_TYPE_MAX,
              "missing entries in the matcher type array");

const char *bf_matcher_type_to_str(enum bf_matcher_type type)
{
    bf_assert(0 <= type && type < _BF_MATCHER_TYPE_MAX);

    return _bf_matcher_type_strs[type];
}

int bf_matcher_type_from_str(const char *str, enum bf_matcher_type *type)
{
    bf_assert(str);
    bf_assert(type);

    for (size_t i = 0; i < _BF_MATCHER_TYPE_MAX; ++i) {
        if (bf_streq(_bf_matcher_type_strs[i], str)) {
            *type = i;
            return 0;
        }
    }

    return -EINVAL;
}

static const char *_bf_matcher_ops_strs[] = {
    [BF_MATCHER_EQ] = "eq",   [BF_MATCHER_NE] = "not",
    [BF_MATCHER_ANY] = "any", [BF_MATCHER_ALL] = "all",
    [BF_MATCHER_IN] = "in",   [BF_MATCHER_RANGE] = "range",
};

static_assert(ARRAY_SIZE(_bf_matcher_ops_strs) == _BF_MATCHER_OP_MAX);

const char *bf_matcher_op_to_str(enum bf_matcher_op op)
{
    bf_assert(0 <= op && op < _BF_MATCHER_OP_MAX);

    return _bf_matcher_ops_strs[op];
}

int bf_matcher_op_from_str(const char *str, enum bf_matcher_op *op)
{
    bf_assert(str);
    bf_assert(op);

    for (size_t i = 0; i < _BF_MATCHER_OP_MAX; ++i) {
        if (bf_streq(_bf_matcher_ops_strs[i], str)) {
            *op = i;
            return 0;
        }
    }

    return -EINVAL;
}

static const char *_bf_matcher_tcp_flags_strs[] = {
    [BF_MATCHER_TCP_FLAG_FIN] = "FIN", [BF_MATCHER_TCP_FLAG_SYN] = "SYN",
    [BF_MATCHER_TCP_FLAG_RST] = "RST", [BF_MATCHER_TCP_FLAG_PSH] = "PSH",
    [BF_MATCHER_TCP_FLAG_ACK] = "ACK", [BF_MATCHER_TCP_FLAG_URG] = "URG",
    [BF_MATCHER_TCP_FLAG_ECE] = "ECE", [BF_MATCHER_TCP_FLAG_CWR] = "CWR",
};

const char *bf_matcher_tcp_flag_to_str(enum bf_matcher_tcp_flag flag)
{
    bf_assert(0 <= flag && flag < _BF_MATCHER_TCP_FLAG_MAX);

    return _bf_matcher_tcp_flags_strs[flag];
}

int bf_matcher_tcp_flag_from_str(const char *str,
                                 enum bf_matcher_tcp_flag *flag)
{
    bf_assert(str);
    bf_assert(flag);

    for (size_t i = 0; i < _BF_MATCHER_TCP_FLAG_MAX; ++i) {
        if (bf_streq(_bf_matcher_tcp_flags_strs[i], str)) {
            *flag = i;
            return 0;
        }
    }

    return -EINVAL;
}
