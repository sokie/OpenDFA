#include "g.h"
#include "des.h"

/* baked keys at DFA RVA 0xA9F0 */
static const uint8_t G_K1[8] = {0x32,0xA4,0x2F,0x34,0x02,0x4F,0x62,0x8A};
static const uint8_t G_K2[8] = {0x9D,0xBF,0x3E,0xFD,0x0E,0x26,0x19,0xA4};

void dfa_g(const uint8_t in[8], uint8_t out[8]){
    tdes_t t;
    tdes_init(&t, G_K1, G_K2);
    q2b(tdes_dec(&t, b2q(in)), out);
}
