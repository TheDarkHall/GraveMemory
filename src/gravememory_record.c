/*
 * gravememory_record.c - portable record-stream / report writer (see gravememory_record.h)
 *
 * 100% platform independent: compiles on Windows (MSVC / mingw) and Linux.
 * Used by gravememory.c and verified on Linux against gm_dump_parser.py.
 */
#include "gravememory_record.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LM_EMPTY_STR "aad3b435b51404eeaad3b435b51404ee"
#define NT_NOPASS_STR "31d6cfe0d16ae931b73c59d7e0c089c0"

static const uint16_t k_empty16[1] = { 0 };

/* ------------------------------------------------------------------ */
/* user record management                                             */
/* ------------------------------------------------------------------ */

void gm_user_free(GM_USER *u)
{
    if (!u)
        return;
    free(u->username);
    free(u->fullname);
    free(u->comment);
    free(u->homedir);
    free(u);
}

void gm_users_free_all(GM_USER **users, uint32_t count)
{
    uint32_t i;
    if (!users)
        return;
    for (i = 0; i < count; i++)
        gm_user_free(users[i]);
    free(users);
}

/* ------------------------------------------------------------------ */
/* low-level writers                                                  */
/* ------------------------------------------------------------------ */

int gm_write_bytes(GM_WRITE_FN fn, void *ctx, const void *buf, uint32_t len)
{
    if (len == 0)
        return 0;
    if (!buf || !fn)
        return 1;
    return fn(ctx, buf, len) ? 1 : 0;
}

int gm_write_u8(GM_WRITE_FN fn, void *ctx, uint8_t v)
{
    return fn(ctx, &v, 1) ? 1 : 0;
}

int gm_write_u32le(GM_WRITE_FN fn, void *ctx, uint32_t v)
{
    uint8_t b[4];
    b[0] = (uint8_t)(v & 0xff);
    b[1] = (uint8_t)((v >> 8) & 0xff);
    b[2] = (uint8_t)((v >> 16) & 0xff);
    b[3] = (uint8_t)((v >> 24) & 0xff);
    return fn(ctx, b, 4) ? 1 : 0;
}

int gm_write_u64le(GM_WRITE_FN fn, void *ctx, uint64_t v)
{
    uint8_t b[8];
    int i;
    for (i = 0; i < 8; i++)
        b[i] = (uint8_t)((v >> (8 * i)) & 0xff);
    return fn(ctx, b, 8) ? 1 : 0;
}

uint32_t gm_strlen16(const uint16_t *s)
{
    uint32_t n = 0;
    if (!s)
        return 0;
    while (s[n])
        n++;
    return n;
}

/* [u32 byte_len (excl. NUL)][byte_len + 2 bytes UTF-16LE incl. NUL] */
int gm_write_utf16_field(GM_WRITE_FN fn, void *ctx, const uint16_t *s)
{
    uint32_t len = gm_strlen16(s) * 2u;
    if (gm_write_u32le(fn, ctx, len))
        return 1;
    if (len > 0) {
        if (fn(ctx, s, len))
            return 1;
    }
    /* NUL terminator (2 bytes) */
    if (gm_write_u8(fn, ctx, 0))
        return 1;
    return gm_write_u8(fn, ctx, 0);
}

int gm_write_domain(GM_WRITE_FN fn, void *ctx, const uint16_t *domain)
{
    return gm_write_utf16_field(fn, ctx, domain);
}

int gm_write_user(GM_WRITE_FN fn, void *ctx, const GM_USER *u)
{
    if (!u)
        return 1;
    if (gm_write_utf16_field(fn, ctx, u->username ? u->username : k_empty16))
        return 1;
    if (gm_write_utf16_field(fn, ctx, u->fullname ? u->fullname : k_empty16))
        return 1;
    if (gm_write_utf16_field(fn, ctx, u->comment ? u->comment : k_empty16))
        return 1;
    if (gm_write_utf16_field(fn, ctx, u->homedir ? u->homedir : k_empty16))
        return 1;
    if (gm_write_u32le(fn, ctx, u->rid))
        return 1;
    /* NT block FIRST (GraveMemory WriteHash order) */
    if (gm_write_u8(fn, ctx, u->has_nt ? 1 : 0))
        return 1;
    if (u->has_nt && gm_write_bytes(fn, ctx, u->nt, 16))
        return 1;
    /* LM block SECOND */
    if (gm_write_u8(fn, ctx, u->has_lm ? 1 : 0))
        return 1;
    if (u->has_lm && gm_write_bytes(fn, ctx, u->lm, 16))
        return 1;
    if (gm_write_u64le(fn, ctx, u->password_last_set))
        return 1;
    if (gm_write_u8(fn, ctx, u->locked_out ? 1 : 0))
        return 1;
    if (gm_write_u8(fn, ctx, u->disabled ? 1 : 0))
        return 1;
    if (gm_write_u8(fn, ctx, u->never_expires ? 1 : 0))
        return 1;
    return gm_write_u8(fn, ctx, u->expired ? 1 : 0);
}

/* ------------------------------------------------------------------ */
/* growing string buffer                                              */
/* ------------------------------------------------------------------ */

int gm_strb_init(GM_STRB *b)
{
    b->cap = 4096;
    b->len = 0;
    b->buf = (char *)malloc(b->cap);
    if (!b->buf)
        return 1;
    b->buf[0] = '\0';
    return 0;
}

void gm_strb_free(GM_STRB *b)
{
    if (b && b->buf) {
        free(b->buf);
        b->buf = NULL;
    }
}

static int strb_reserve(GM_STRB *b, size_t extra)
{
    size_t need = b->len + extra + 1;
    if (need <= b->cap)
        return 0;
    while (b->cap < need)
        b->cap *= 2;
    b->buf = (char *)realloc(b->buf, b->cap);
    return b->buf ? 0 : 1;
}

int gm_strb_putc(GM_STRB *b, char c)
{
    if (strb_reserve(b, 1))
        return 1;
    b->buf[b->len++] = c;
    b->buf[b->len] = '\0';
    return 0;
}

int gm_strb_puts(GM_STRB *b, const char *s)
{
    size_t n = strlen(s);
    if (strb_reserve(b, n))
        return 1;
    memcpy(b->buf + b->len, s, n);
    b->len += n;
    b->buf[b->len] = '\0';
    return 0;
}

/* ------------------------------------------------------------------ */
/* string helpers                                                     */
/* ------------------------------------------------------------------ */

char *gm_utf16_to_utf8(const uint16_t *s)
{
    GM_STRB b;
    uint32_t i, n;

    if (!s)
        return NULL;
    if (gm_strb_init(&b))
        return NULL;

    n = gm_strlen16(s);
    for (i = 0; i < n; i++) {
        uint32_t cp;
        uint16_t c = s[i];

        if (c >= 0xd800u && c <= 0xdbffu && i + 1 < n &&
            s[i + 1] >= 0xdc00u && s[i + 1] <= 0xdfffu) {
            /* surrogate pair */
            cp = 0x10000u + (((uint32_t)(c - 0xd800u)) << 10) +
                 (uint32_t)(s[i + 1] - 0xdc00u);
            i++;
        } else if (c >= 0xd800u && c <= 0xdfffu) {
            cp = 0xfffdu; /* lone surrogate -> replacement character */
        } else {
            cp = c;
        }

        if (cp < 0x80u) {
            if (gm_strb_putc(&b, (char)cp))
                goto fail;
        } else if (cp < 0x800u) {
            if (gm_strb_putc(&b, (char)(0xc0 | (cp >> 6))) ||
                gm_strb_putc(&b, (char)(0x80 | (cp & 0x3f))))
                goto fail;
        } else if (cp < 0x10000u) {
            if (gm_strb_putc(&b, (char)(0xe0 | (cp >> 12))) ||
                gm_strb_putc(&b, (char)(0x80 | ((cp >> 6) & 0x3f))) ||
                gm_strb_putc(&b, (char)(0x80 | (cp & 0x3f))))
                goto fail;
        } else {
            if (gm_strb_putc(&b, (char)(0xf0 | (cp >> 18))) ||
                gm_strb_putc(&b, (char)(0x80 | ((cp >> 12) & 0x3f))) ||
                gm_strb_putc(&b, (char)(0x80 | ((cp >> 6) & 0x3f))) ||
                gm_strb_putc(&b, (char)(0x80 | (cp & 0x3f))))
                goto fail;
        }
    }
    return b.buf;
fail:
    gm_strb_free(&b);
    return NULL;
}

char *gm_hex_lower(const uint8_t *data, uint32_t len)
{
    static const char hexd[] = "0123456789abcdef";
    char *s = (char *)malloc((size_t)len * 2 + 1);
    uint32_t i;
    if (!s)
        return NULL;
    for (i = 0; i < len; i++) {
        s[i * 2] = hexd[(data[i] >> 4) & 0xf];
        s[i * 2 + 1] = hexd[data[i] & 0xf];
    }
    s[len * 2] = '\0';
    return s;
}

/* days-since-epoch -> civil date (Howard Hinnant's algorithm) */
static void civil_from_days(int64_t z, int *y, int *m, int *d)
{
    int64_t era, y_;
    unsigned doe, yoe, doy, mp, d_, m_;

    z += 719468;
    era = (z >= 0 ? z : z - 146096) / 146097;
    doe = (unsigned)(z - era * 146097);
    yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    y_ = era * 400 + (int64_t)yoe;
    doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    mp = (5 * doy + 2) / 153;
    d_ = doy - (153 * mp + 2) / 5 + 1;
    m_ = (mp < 10) ? mp + 3 : mp - 9;
    *y = (int)(y_ + (m_ <= 2));
    *m = (int)m_;
    *d = (int)d_;
}

char *gm_filetime_to_iso(uint64_t ft)
{
    int64_t secs100, secs, days, rem;
    int y, m, d, hh, mm, ss;
    char *s;

    if (ft == 0)
        return NULL;

    secs100 = (int64_t)ft - 116444736000000000LL;
    if (secs100 < 0)
        return NULL;

    secs = secs100 / 10000000LL;
    days = secs / 86400;
    rem = secs % 86400;
    if (rem < 0) {
        rem += 86400;
        days -= 1;
    }
    if (days > 2932896) /* far beyond year 9999 */
        return NULL;

    civil_from_days(days, &y, &m, &d);
    if (y < 1601 || y > 9999)
        return NULL;

    hh = (int)(rem / 3600);
    mm = (int)((rem / 60) % 60);
    ss = (int)(rem % 60);

    s = (char *)malloc(48);
    if (!s)
        return NULL;
    snprintf(s, 48, "%04d-%02d-%02d %02d:%02d:%02d UTC", y, m, d, hh, mm, ss);
    return s;
}

const char *gm_lm_note(const char *lm_hex)
{
    if (!lm_hex)
        return NULL;
    if (strcmp(lm_hex, LM_EMPTY_STR) == 0)
        return "No Password";
    if (strncmp(lm_hex, "aad3b435b51404ee", 16) == 0)
        return "second half set";
    if (strlen(lm_hex) == 32 && strcmp(lm_hex + 16, "aad3b435b51404ee") == 0)
        return "first half set";
    return NULL;
}

const char *gm_nt_note(const char *nt_hex)
{
    if (!nt_hex)
        return NULL;
    if (strcmp(nt_hex, NT_NOPASS_STR) == 0)
        return "No Password";
    return NULL;
}

/* ------------------------------------------------------------------ */
/* string-buffer JSON helpers                                         */
/* ------------------------------------------------------------------ */

int gm_strb_put_json_utf16(GM_STRB *b, const uint16_t *s)
{
    char *u8 = gm_utf16_to_utf8(s ? s : k_empty16);
    const unsigned char *p;
    char tmp[8];
    int rc = 0;

    if (!u8)
        return 1;
    if (gm_strb_putc(b, '"')) {
        rc = 1;
        goto out;
    }
    for (p = (const unsigned char *)u8; *p; p++) {
        unsigned char c = *p;
        if (c == '"') {
            if (gm_strb_puts(b, "\\\"")) { rc = 1; goto out; }
        } else if (c == '\\') {
            if (gm_strb_puts(b, "\\\\")) { rc = 1; goto out; }
        } else if (c < 0x20) {
            snprintf(tmp, sizeof(tmp), "\\u%04x", (unsigned)c);
            if (gm_strb_puts(b, tmp)) { rc = 1; goto out; }
        } else {
            if (gm_strb_putc(b, (char)c)) { rc = 1; goto out; }
        }
    }
    if (gm_strb_putc(b, '"'))
        rc = 1;
out:
    free(u8);
    return rc;
}

/* plain (already UTF-8) C string as a JSON string */
static int strb_put_json_str(GM_STRB *b, const char *s)
{
    GM_STRB tmp;
    size_t i;
    int rc = 0;

    if (!s) {
        return gm_strb_puts(b, "null");
    }
    if (gm_strb_init(&tmp))
        return 1;
    if (gm_strb_putc(&tmp, '"') || gm_strb_puts(&tmp, s) ||
        gm_strb_putc(&tmp, '"')) {
        rc = 1;
        goto out;
    }
    /* escape the payload inside the quotes */
    {
        GM_STRB out;
        if (gm_strb_init(&out)) { rc = 1; goto out; }
        if (gm_strb_putc(&out, '"')) { rc = 1; goto out2; }
        for (i = 1; i < tmp.len - 1; i++) {
            char c = tmp.buf[i];
            if (c == '"' || c == '\\') {
                if (gm_strb_putc(&out, '\\') || gm_strb_putc(&out, c)) { rc = 1; goto out2; }
            } else if ((unsigned char)c < 0x20) {
                char esc[8];
                snprintf(esc, sizeof(esc), "\\u%04x", (unsigned char)c);
                if (gm_strb_puts(&out, esc)) { rc = 1; goto out2; }
            } else {
                if (gm_strb_putc(&out, c)) { rc = 1; goto out2; }
            }
        }
        if (gm_strb_putc(&out, '"') || gm_strb_puts(b, out.buf))
            rc = 1;
out2:
        gm_strb_free(&out);
    }
out:
    gm_strb_free(&tmp);
    return rc;
}

static int strb_puts_u32(GM_STRB *b, uint32_t v)
{
    char tmp[16];
    snprintf(tmp, sizeof(tmp), "%u", (unsigned)v);
    return gm_strb_puts(b, tmp);
}

static int strb_puts_u64(GM_STRB *b, uint64_t v)
{
    char tmp[24];
    snprintf(tmp, sizeof(tmp), "%llu", (unsigned long long)v);
    return gm_strb_puts(b, tmp);
}

static int strb_puts_bool(GM_STRB *b, int v)
{
    return gm_strb_puts(b, v ? "true" : "false");
}

/* truncate UTF-8 at max display width without splitting a sequence */
static void utf8_trunc(char *dst, size_t dstcap, const char *src, size_t maxlen)
{
    size_t i = 0;
    if (dstcap == 0)
        return;
    while (i < maxlen && src[i] && i + 1 < dstcap)
        i++;
    /* back off continuation bytes */
    while (i > 0 && ((unsigned char)src[i] & 0xc0) == 0x80)
        i--;
    if (i + 1 > dstcap - 1)
        i = dstcap - 1;
    memcpy(dst, src, i);
    dst[i] = '\0';
}

static int build_user_json(GM_STRB *b, const GM_USER *u)
{
    char *nt_hex = u->has_nt ? gm_hex_lower(u->nt, 16) : NULL;
    char *lm_hex = u->has_lm ? gm_hex_lower(u->lm, 16) : NULL;
    char *iso = gm_filetime_to_iso(u->password_last_set);
    int rc = 1;

    if (gm_strb_puts(b, "    {\n      \"username\": "))
        goto out;
    if (gm_strb_put_json_utf16(b, u->username))
        goto out;
    if (gm_strb_puts(b, ",\n      \"rid\": "))
        goto out;
    if (strb_puts_u32(b, u->rid))
        goto out;
    if (gm_strb_puts(b, ",\n      \"fullname\": "))
        goto out;
    if (gm_strb_put_json_utf16(b, u->fullname))
        goto out;
    if (gm_strb_puts(b, ",\n      \"admin_comment\": "))
        goto out;
    if (gm_strb_put_json_utf16(b, u->comment))
        goto out;
    if (gm_strb_puts(b, ",\n      \"home_dir\": "))
        goto out;
    if (gm_strb_put_json_utf16(b, u->homedir))
        goto out;
    if (gm_strb_puts(b, ",\n      \"nt_present\": "))
        goto out;
    if (strb_puts_bool(b, u->has_nt))
        goto out;
    if (gm_strb_puts(b, ",\n      \"lm_present\": "))
        goto out;
    if (strb_puts_bool(b, u->has_lm))
        goto out;
    if (gm_strb_puts(b, ",\n      \"nt_hex\": "))
        goto out;
    if (strb_put_json_str(b, nt_hex))
        goto out;
    if (gm_strb_puts(b, ",\n      \"lm_hex\": "))
        goto out;
    if (strb_put_json_str(b, lm_hex))
        goto out;
    if (gm_strb_puts(b, ",\n      \"nt_note\": "))
        goto out;
    if (strb_put_json_str(b, gm_nt_note(nt_hex)))
        goto out;
    if (gm_strb_puts(b, ",\n      \"lm_note\": "))
        goto out;
    if (strb_put_json_str(b, gm_lm_note(lm_hex)))
        goto out;
    if (gm_strb_puts(b, ",\n      \"password_last_set\": "))
        goto out;
    if (strb_put_json_str(b, iso))
        goto out;
    if (gm_strb_puts(b, ",\n      \"password_last_set_raw\": "))
        goto out;
    if (strb_puts_u64(b, u->password_last_set))
        goto out;
    if (gm_strb_puts(b, ",\n      \"flags\": {\n        \"locked_out\": "))
        goto out;
    if (strb_puts_bool(b, u->locked_out))
        goto out;
    if (gm_strb_puts(b, ",\n        \"disabled\": "))
        goto out;
    if (strb_puts_bool(b, u->disabled))
        goto out;
    if (gm_strb_puts(b, ",\n        \"never_expires\": "))
        goto out;
    if (strb_puts_bool(b, u->never_expires))
        goto out;
    if (gm_strb_puts(b, ",\n        \"expired\": "))
        goto out;
    if (strb_puts_bool(b, u->expired))
        goto out;
    if (gm_strb_puts(b, "\n      }\n    }"))
        goto out;
    rc = 0;
out:
    free(nt_hex);
    free(lm_hex);
    free(iso);
    return rc;
}

char *gm_build_json(const char *domain,
                     const GM_USER *const *users,
                     uint32_t count,
                     int records_complete)
{
    GM_STRB b;
    uint32_t i;

    if (gm_strb_init(&b))
        return NULL;
    if (gm_strb_puts(&b,
                      "{\n  \"tool\": \"GraveMemory 1.2\",\n"
                      "  \"format\": \"GM-compatible record stream - PLAINTEXT"
                      " (no container) \",\n  \"domain\": "))
        goto fail;
    if (strb_put_json_str(&b, domain))
        goto fail;
    if (gm_strb_puts(&b, ",\n  \"user_count\": "))
        goto fail;
    if (strb_puts_u32(&b, count))
        goto fail;
    if (gm_strb_puts(&b, ",\n  \"records_complete\": "))
        goto fail;
    if (strb_puts_bool(&b, records_complete))
        goto fail;
    if (gm_strb_puts(&b, ",\n  \"users\": [\n"))
        goto fail;
    for (i = 0; i < count; i++) {
        if (i > 0 && gm_strb_puts(&b, ",\n"))
            goto fail;
        if (build_user_json(&b, users[i]))
            goto fail;
    }
    if (gm_strb_puts(&b, "\n  ]\n}\n"))
        goto fail;
    return b.buf;
fail:
    gm_strb_free(&b);
    return NULL;
}

char *gm_build_pwdump(const GM_USER *const *users, uint32_t count)
{
    GM_STRB b;
    uint32_t i;

    if (gm_strb_init(&b))
        return NULL;
    for (i = 0; i < count; i++) {
        const GM_USER *u = users[i];
        char *name = gm_utf16_to_utf8(u->username ? u->username : k_empty16);
        char *nt_hex = u->has_nt ? gm_hex_lower(u->nt, 16) : NULL;
        char *lm_hex = u->has_lm ? gm_hex_lower(u->lm, 16) : NULL;
        char line[1024];

        /* usernames cannot contain ':' (SAM restriction) - no escaping needed */
        snprintf(line, sizeof(line), "%s:%u:%s:%s:::\n",
                 name ? name : "?", (unsigned)u->rid,
                 lm_hex ? lm_hex : LM_EMPTY_STR,
                 nt_hex ? nt_hex : NT_NOPASS_STR);
        if (gm_strb_puts(&b, line)) {
            free(name);
            free(nt_hex);
            free(lm_hex);
            goto fail;
        }
        free(name);
        free(nt_hex);
        free(lm_hex);
    }
    return b.buf;
fail:
    gm_strb_free(&b);
    return NULL;
}

char *gm_build_table(const char *domain, const GM_USER *const *users,
                      uint32_t count, int records_complete)
{
    GM_STRB b;
    uint32_t i;
    char *pwdump;

    if (gm_strb_init(&b))
        return NULL;
    if (gm_strb_puts(&b,
                      "==============================================================\n"
                      "gravememory - plaintext SAM dump  (GM-compatible, no encryption)\n"
                      "==============================================================\n"))
        goto fail;
    if (gm_strb_puts(&b, "Domain            : ") || gm_strb_puts(&b, domain ? domain : ""))
        goto fail;
    if (gm_strb_puts(&b, "\nUsers             : "))
        goto fail;
    if (strb_puts_u32(&b, count))
        goto fail;
    if (gm_strb_puts(&b, records_complete
                               ? " (records complete)\n"
                               : " (INCOMPLETE - dump was interrupted!)\n"))
        goto fail;
    if (gm_strb_puts(&b,
                      "--------------------------------------------------------------\n"
                      "  USERNAME                 RID     FLG  NT"
                      "                                   LM\n"
                      "--------------------------------------------------------------\n"))
        goto fail;
    for (i = 0; i < count; i++) {
        const GM_USER *u = users[i];
        char *name = gm_utf16_to_utf8(u->username ? u->username : k_empty16);
        char *nt_hex = u->has_nt ? gm_hex_lower(u->nt, 16) : NULL;
        char *lm_hex = u->has_lm ? gm_hex_lower(u->lm, 16) : NULL;
        char namebuf[24];
        char flg[5];
        char line[256];

        utf8_trunc(namebuf, sizeof(namebuf), name ? name : "?", 22);
        flg[0] = u->locked_out ? 'L' : '.';
        flg[1] = u->disabled ? 'D' : '.';
        flg[2] = u->never_expires ? 'E' : '.';
        flg[3] = u->expired ? 'X' : '.';
        flg[4] = '\0';
        snprintf(line, sizeof(line), "  %-22s %-7u %-4s %-33s %-33s\n",
                 namebuf, (unsigned)u->rid, flg,
                 nt_hex ? nt_hex : "-",
                 lm_hex ? lm_hex : "-");
        if (gm_strb_puts(&b, line)) {
            free(name);
            free(nt_hex);
            free(lm_hex);
            goto fail;
        }
        free(name);
        free(nt_hex);
        free(lm_hex);
    }
    if (gm_strb_puts(&b,
                      "--------------------------------------------------------------\n"
                      "FLAGS: L=locked_out D=disabled E=never_expires X=expired\n"
                      "pwdump format (user:RID:LM:NT:::):\n"))
        goto fail;
    pwdump = gm_build_pwdump(users, count);
    if (pwdump) {
        int perr = gm_strb_puts(&b, pwdump);
        free(pwdump);
        if (perr)
            goto fail;
    }
    return b.buf;
fail:
    gm_strb_free(&b);
    return NULL;
}
