#ifndef NONO_LOG_H
#define NONO_LOG_H

/* Define DEBUG (or build with /DDEBUG) to enable file/OutputDebugString logging. */
#ifdef DEBUG
static HANDLE g_log;

static DWORD log_strlen(const char* s) {
    DWORD n;

    n = 0;
    while (s[n]) n++;
    return n;
}

static void log_path(char* dst) {
    static const u8 packed[] = {
        0x34, 0x35, 0x34, 0x35, 0x05, 0x32, 0x35,
        0x35, 0x31, 0x74, 0x36, 0x35, 0x3D
    };
    int i;

    for (i = 0; i < (int)sizeof(packed); i++) {
        dst[i] = (char)(packed[i] ^ 0x5A);
    }
    dst[sizeof(packed)] = 0;
}

static void log_open(void) {
    char path[16];

    if (!g_api.CreateFileA) return;
    log_path(path);
    g_log = g_api.CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ,
                              NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
}

static void log_s(const char* s) {
    DWORD n;
    if (g_api.OutputDebugStringA) g_api.OutputDebugStringA(s);
    if (g_api.WriteFile && g_log != INVALID_HANDLE_VALUE)
        g_api.WriteFile(g_log, s, log_strlen(s), &n, NULL);
}

static void log_x64(const char* lbl, unsigned __int64 v) {
    char     buf[80];
    char     hex[17];
    char*    p;
    const char* q;
    int      i;
    unsigned __int64 tmp = v;
    for (i = 15; i >= 0; i--) {
        hex[i] = "0123456789ABCDEF"[tmp & 0xF];
        tmp >>= 4;
    }
    hex[16] = '\0';
    p = buf; q = lbl;
    while (*q) *p++ = *q++;
    *p++ = '='; *p++ = '0'; *p++ = 'x';
    q = hex; while (*q) *p++ = *q++;
    *p++ = '\n'; *p++ = '\0';
    log_s(buf);
}

static void log_d(const char* lbl, int v) {
    char        buf[80];
    char        digs[12];
    char*       p;
    const char* q;
    int         neg = (v < 0);
    unsigned int u  = neg ? (unsigned int)(-v) : (unsigned int)v;
    int          i  = 11;
    digs[--i] = '\0';
    if (u == 0) { digs[--i] = '0'; }
    else { while (u) { digs[--i] = '0' + u % 10; u /= 10; } }
    if (neg) digs[--i] = '-';
    p = buf; q = lbl;
    while (*q) *p++ = *q++;
    *p++ = '=';
    q = digs + i; while (*q) *p++ = *q++;
    *p++ = '\n'; *p++ = '\0';
    log_s(buf);
}

static void log_bytes(const char* lbl, const u8* data, int n) {
    char        buf[256];
    char*       p = buf;
    const char* q = lbl;
    int         i;
    while (*q && p < buf + 200) *p++ = *q++;
    *p++ = ':'; *p++ = ' ';
    for (i = 0; i < n && p < buf + 240; i++) {
        *p++ = "0123456789ABCDEF"[data[i] >> 4];
        *p++ = "0123456789ABCDEF"[data[i] & 0xF];
        *p++ = ' ';
    }
    *p++ = '\n'; *p++ = '\0';
    log_s(buf);
}
#else
#define log_open() ((void)0)
#define log_s(s) ((void)0)
#define log_x64(lbl, v) ((void)0)
#define log_d(lbl, v) ((void)0)
#define log_bytes(lbl, data, n) ((void)0)
#endif

#endif
