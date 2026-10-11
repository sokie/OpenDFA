#include <windows.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include "des.h"
#include "g.h"

static const uint8_t VP36_K1[8]={0xE6,0x2A,0x98,0xBF,0x52,0xB6,0xF2,0x37};
static const uint8_t VP36_K2[8]={0xCE,0x4C,0xF7,0x04,0x8C,0x07,0x80,0x80};

static uint8_t STATEMENT[40]={
 0x00,0x00,0x00,0x00, 0x67,0xAC,0x34,0x5B,0xAD,0xE5,0x10,0x4F,0xB4,0x19,0xF2,0xAF,0x24,0x83,0x4D,0x1A,
 0x02,0x00,0x00,0x00, 0x01,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x03,0x00,0x00,0x00, 0x00,0x00,0x00,0x00};

static void nonce_header(const tdes_t* vp, const uint8_t* in, uint8_t hdr[16]){
    uint8_t prev[8]; memcpy(prev,in+0x30,8);
    for(int blk=0;blk<2;blk++){
        const uint8_t* c=in+0x38+blk*8;
        uint8_t p[8]; q2b(tdes_dec(vp,b2q(c)),p);
        for(int i=0;i<8;i++) hdr[blk*8+i]=p[i]^prev[i];
        memcpy(prev,c,8);
    }
}

static void u_op1(const uint8_t* in, uint8_t* out, uint8_t ha[16]){
    tdes_t vp; tdes_init(&vp,VP36_K1,VP36_K2);
    static const uint8_t hdr[16]={1,0,0,0, 1,0,0,0, 0x48,0,0,0, 0,0,0,0};
    uint8_t pt[56];
    nonce_header(&vp,in,pt);
    memcpy(ha,pt,16);
    memcpy(pt+16,STATEMENT,40);
    memcpy(out,hdr,16);
    memcpy(out+0x10,in+0x38,16);                   /* echo in[0x38:0x48] */
    tdes_cbc_encrypt(&vp,in+0x40,pt,out+0x20,56);  /* response IV = in[0x40:0x48] */
}

static uint8_t g_seed[24];
static volatile LONG g_seed_ready = 0;

static void seed_from_ha(const uint8_t ha[16], const uint8_t* in)
{
    uint8_t msg[24], iv[8];
    memcpy(msg,ha,16);
    memcpy(msg + 16,in + 0x38,8);         /* nonce B low half */
    memcpy(iv,in + 0x30,8);               /* the request's license IV */
    tdes_t vp; tdes_init(&vp,VP36_K1,VP36_K2);
    tdes_cbc_encrypt(&vp,iv,msg,g_seed,24);
    InterlockedExchange(&g_seed_ready,1);
}

static void e_head(uint32_t seq, uint32_t x, uint32_t y, uint8_t* out)
{
    uint8_t K0[8], K1[8], IV[8];
    dfa_g(g_seed, K0);
    dfa_g(g_seed + 8, K1);
    dfa_g(g_seed + 16, IV);
    uint8_t P[16];
    memcpy(P,&x,4);
    memcpy(P + 4,&seq,4);
    memcpy(P + 8,&y,4);
    memset(P + 12,0,4);
    tdes_t t; tdes_init(&t,K0,K1);
    tdes_cbc_encrypt(&t,IV,P,out,16);
}

static int g_verbose = -1;
static long g_ucalls = 0, g_ecalls = 0;

static void OLog(const char* fmt, ...){
    if (g_verbose < 0) {
        char mp[MAX_PATH]; HMODULE self = 0;
        GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCSTR)&OLog, &self);
        if (!GetModuleFileNameA(self, mp, MAX_PATH)) { g_verbose = 0; return; }
        char* slash = strrchr(mp, '\\');
        if (!slash) { g_verbose = 0; return; }
        strcpy(slash + 1, "opendfa.verbose");
        g_verbose = (GetFileAttributesA(mp) != INVALID_FILE_ATTRIBUTES) ? 1 : 0;
    }
    if (!g_verbose) return;
    char lp[MAX_PATH]; HMODULE self2 = 0;
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCSTR)&OLog, &self2);
    if (!GetModuleFileNameA(self2, lp, MAX_PATH)) return;
    char* slash2 = strrchr(lp, '\\');
    if (!slash2) return;
    strcpy(slash2 + 1, "opendfa.log");
    FILE* f = fopen(lp, "a");
    if (!f) return;
    SYSTEMTIME st; GetLocalTime(&st);
    fprintf(f, "[%02d:%02d:%02d.%03d] ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    va_list ap; va_start(ap, fmt); vfprintf(f, fmt, ap); va_end(ap);
    fputc('\n', f); fclose(f);
}

int __stdcall dfa_u(uint32_t* in, uint32_t* out, uint32_t len, void* st, void* a4, void* ctx){
    (void)len;(void)st;(void)a4;(void)ctx;
    long n = InterlockedIncrement(&g_ucalls);
    if (in && out && in[0]==1){
        /* statement = 00000000 + request GUID + constant flags */
        static const uint8_t flags[24]={2,0,0,0, 1,0,0,0, 0,0,0,0, 3,0,0,0, 0,0,0,0, 0,0,0,0};
        uint8_t ha[16];
        memcpy(STATEMENT+4, in+4, 16);
        memcpy(STATEMENT+20, flags, 20);
        u_op1((const uint8_t*)in,(uint8_t*)out,ha);
        seed_from_ha(ha,(const uint8_t*)in);
        OLog("u op1 #%ld: reply out[0x20..0x28]=%02X%02X%02X%02X%02X%02X%02X%02X",
            n, ((uint8_t*)out)[0x20], ((uint8_t*)out)[0x21], ((uint8_t*)out)[0x22], ((uint8_t*)out)[0x23],
            ((uint8_t*)out)[0x24], ((uint8_t*)out)[0x25], ((uint8_t*)out)[0x26], ((uint8_t*)out)[0x27]);
    } else OLog("u op%u (not op1) #%ld len=%u", in ? in[0] : 0xFFFFFFFF, n, len);
    return 1;
}

static void e_apply_contract(uint32_t len, void* st){
    if (!st) return;
    __try {
        uint32_t v = ((volatile uint32_t*)st)[0] & ~0x00000400u;
        if (len >= 168) v |= 0x8u;
        else if (len >= 132) v |= 0x2u;
        ((volatile uint32_t*)st)[0] = v;
    } __except(EXCEPTION_EXECUTE_HANDLER){ /* unreadable state: leave it */ }
}

static void read_path(void* st, char* path, int cap){
    path[0] = 0;
    if (!st) return;
    __try {
        const char* p = (const char*)st + 0x5C;
        int i;
        for (i = 0; i < cap - 1 && p[i]; ++i) { path[i] = p[i]; path[i + 1] = 0; }
    } __except(EXCEPTION_EXECUTE_HANDLER){ path[0] = 0; }
}

static int e_compute(uint32_t* in, uint32_t* out, uint32_t len, void* st, uint32_t seq, void* ctx){
    (void)in; (void)st; (void)ctx;
    if (g_seed_ready && out && len >= 16 && len <= 0x400)
        e_head(seq, 1, 0, (uint8_t*)out);
    return 1;
}

int __stdcall dfa_e_body(uint32_t* in, uint32_t* out, uint32_t len, void* st, uint32_t seq, void* ctx){
    long n = InterlockedIncrement(&g_ecalls);
    char path[80];
    read_path(st, path, (int)sizeof(path));
    e_apply_contract(len, st);
    e_compute(in, out, len, st, seq, ctx);
    if (out && len >= 4)
        OLog("e #%ld len=%u seq=%u compute head=%02X%02X%02X%02X path=\"%s\"",
            n, len, seq, ((uint8_t*)out)[0], ((uint8_t*)out)[1],
            ((uint8_t*)out)[2], ((uint8_t*)out)[3], path[0] ? path : "(none)");
    else
        OLog("e #%ld len=%u seq=%u compute path=\"%s\"", n, len, seq, path[0] ? path : "(none)");
    return 1;
}

int __stdcall dfa_e(uint32_t* in, uint32_t* out, uint32_t len, void* st, uint32_t seq, void* ctx){
    return dfa_e_body(in, out, len, st, seq, ctx);
}

BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID p){
    (void)p;
    if (r == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        OLog("==== OpenDFA-minimal loaded (computed e head, static out-tail/state contract) ====");
    }
    return TRUE;
}
