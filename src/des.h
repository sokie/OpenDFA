#ifndef OPENDFA_DES_H
#define OPENDFA_DES_H

#include <stdint.h>
#include <stddef.h>

typedef struct { uint64_t k1[16], k2[16]; } tdes_t;

void tdes_init(tdes_t* t, const uint8_t K1[8], const uint8_t K2[8]);

uint64_t tdes_enc(const tdes_t* t, uint64_t x);
uint64_t tdes_dec(const tdes_t* t, uint64_t x);

/* len is truncated to a multiple of 8 */
void tdes_cbc_encrypt(const tdes_t* t, const uint8_t iv[8], const uint8_t* in, uint8_t* out, size_t len);
void tdes_cbc_decrypt(const tdes_t* t, const uint8_t iv[8], const uint8_t* in, uint8_t* out, size_t len);

uint64_t b2q(const uint8_t* b);
void q2b(uint64_t q, uint8_t* b);

#endif
