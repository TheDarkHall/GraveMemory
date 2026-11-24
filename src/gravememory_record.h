/*
 * gravememory_record.h - portable record-stream / report writer for gravememory
 *
 * This layer is 100% platform-independent (compiles on Windows and Linux)
 * so the exact byte format of gravememory.dmp can be verified end-to-end
 * against gm_dump_parser.py without a Windows machine.
 *
 * The record stream follows the classic GraveMemory record layout
 * (writer: gravememory_record.c, reader: gm_dump_parser.py):
 *
 *   record #0: domain   -> [u32 byte_len][byte_len + 2 bytes UTF-16LE incl. NUL]
 *   per user:
 *        username       -> [u32 byte_len][bytes + NUL]
 *        fullname       -> [u32 byte_len][bytes + NUL]
 *        admin_comment  -> [u32 byte_len][bytes + NUL]
 *        home_dir       -> [u32 byte_len][bytes + NUL]
 *        rid            -> u32 LE
 *        NT present     -> u8 (1|0)          <-- NT block FIRST
 *        NT OWF         -> 16 bytes (if present)
 *        LM present     -> u8 (1|0)          <-- LM block SECOND
 *        LM OWF         -> 16 bytes (if present)
 *        password_last_set -> u64 LE (FILETIME, raw)
 *        locked_out     -> u8
 *        disabled       -> u8
 *        never_expires  -> u8
 *        expired        -> u8
 *
 * The ONLY thing this rewrite removes compared to the legacy sealed
 * GraveMemory container design is the RSA-2048 + AES-256-CBC layer.
 * No encryption.
 *
 * AUTHORIZED USE ONLY - for auditing systems you own or have explicit
 * written permission to assess.
 */
#ifndef GMRECORD_H
#define GMRECORD_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* record sink                                                        */
/* ------------------------------------------------------------------ */

/* write callback: return 0 on success, nonzero on failure */
typedef int (*GM_WRITE_FN)(void *ctx, const void *buf, uint32_t len);

/* ------------------------------------------------------------------ */
/* one user record (all strings are UTF-16LE uint16_t[], NUL-terminated) */
/* ------------------------------------------------------------------ */

typedef struct {
    uint16_t *username;             /* malloc'd */
    uint16_t *fullname;
    uint16_t *comment;
    uint16_t *homedir;
    uint32_t  rid;
    int       has_nt;
    uint8_t   nt[16];
    int       has_lm;
    uint8_t   lm[16];
    uint64_t  password_last_set;    /* raw FILETIME (0 = never) */
    int       locked_out;
    int       disabled;
    int       never_expires;
    int       expired;
} GM_USER;

void gm_user_free(GM_USER *u);
void gm_users_free_all(GM_USER **users, uint32_t count);

/* ------------------------------------------------------------------ */
/* plaintext record stream primitives                                 */
/* ------------------------------------------------------------------ */

int gm_write_utf16_field(GM_WRITE_FN fn, void *ctx, const uint16_t *s);
int gm_write_u8(GM_WRITE_FN fn, void *ctx, uint8_t v);
int gm_write_u32le(GM_WRITE_FN fn, void *ctx, uint32_t v);
int gm_write_u64le(GM_WRITE_FN fn, void *ctx, uint64_t v);
int gm_write_bytes(GM_WRITE_FN fn, void *ctx, const void *buf, uint32_t len);

/* first record of the stream (same encoding as any string field) */
int gm_write_domain(GM_WRITE_FN fn, void *ctx, const uint16_t *domain);

/* full per-user record */
int gm_write_user(GM_WRITE_FN fn, void *ctx, const GM_USER *u);

/* ------------------------------------------------------------------ */
/* helpers                                                            */
/* ------------------------------------------------------------------ */

uint32_t gm_strlen16(const uint16_t *s);

/* malloc'd NUL-terminated UTF-8 (caller frees); handles surrogate pairs */
char *gm_utf16_to_utf8(const uint16_t *s);

/* malloc'd lowercase hex (2*len + 1 bytes) */
char *gm_hex_lower(const uint8_t *data, uint32_t len);

/* malloc'd "YYYY-MM-DD HH:MM:SS UTC" or NULL when ft == 0 / out of range */
char *gm_filetime_to_iso(uint64_t ft);

/* well-known no-password OWF markers (plain-hash space) */
const char *gm_lm_note(const char *lm_hex);   /* NULL or explanation */
const char *gm_nt_note(const char *nt_hex);

/* ------------------------------------------------------------------ */
/* growing string buffer                                              */
/* ------------------------------------------------------------------ */

typedef struct {
    char  *buf;
    size_t len;
    size_t cap;
} GM_STRB;

int  gm_strb_init(GM_STRB *b);
void gm_strb_free(GM_STRB *b);
int  gm_strb_puts(GM_STRB *b, const char *s);      /* raw */
int  gm_strb_putc(GM_STRB *b, char c);
int  gm_strb_put_json_utf16(GM_STRB *b, const uint16_t *s); /* UTF-8 + JSON-escape */

/* ------------------------------------------------------------------ */
/* report builders (malloc'd, caller frees)                           */
/* ------------------------------------------------------------------ */

/* full JSON report (pretty-printed, UTF-8) */
char *gm_build_json(const char *domain,
                     const GM_USER *const *users,
                     uint32_t count,
                     int records_complete);

/* pwdump-style lines: user:RID:LM:NT::: */
char *gm_build_pwdump(const GM_USER *const *users, uint32_t count);

/* human-readable console table (UTF-8) */
char *gm_build_table(const char *domain,
                      const GM_USER *const *users,
                      uint32_t count,
                      int records_complete);

#ifdef __cplusplus
}
#endif
#endif /* GMRECORD_H */
