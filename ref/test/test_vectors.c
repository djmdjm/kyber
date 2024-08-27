/* Deterministic randombytes by Daniel J. Bernstein */
/* taken from SUPERCOP (https://bench.cr.yp.to)     */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "../kem.h"
#include "../randombytes.h"
#include "../fips202.h"

#define NTESTS 10000


/* Initital state after absorbing empty string 
 * Permute before squeeze is achieved by setting pos to SHAKE128_RATE */
static keccak_state rngstate = {{0x1F, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (1ULL << 63), 0, 0, 0, 0}, SHAKE128_RATE};

void randombytes(uint8_t *x,size_t xlen)
{
  size_t i;
  shake128_squeeze(x, xlen, &rngstate);
  for(i=0;i<xlen;i++)
    printf("%02x",x[i]);
}

int main(void)
{
  unsigned int i,j;
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t key_a[CRYPTO_BYTES];
  uint8_t key_b[CRYPTO_BYTES];
  uint8_t h[32];

  printf("[\n");
  for(i=0;i<NTESTS;i++) {
    printf("    {\n");
    // Key-pair generation
    printf("        \"key_generation_seed\": \"");
    crypto_kem_keypair(pk, sk);
    printf("\",\n");
    printf("        \"sha3_256_hash_of_public_key\": \"");
    sha3_256(h, pk, sizeof(pk));
    for(j=0;j<sizeof(h);j++)
      printf("%02x",h[j]);
    printf("\",\n");
    printf("        \"sha3_256_hash_of_secret_key\": \"");
    sha3_256(h, sk, sizeof(sk));
    for(j=0;j<sizeof(h);j++)
      printf("%02x",h[j]);
    printf("\",\n");

    // Encapsulation
    printf("        \"encapsulation_seed\": \"");
    crypto_kem_enc(ct, key_b, pk);
    printf("\",\n");
    printf("        \"sha3_256_hash_of_ciphertext\": \"");
    sha3_256(h, ct, sizeof(ct));
    for(j=0;j<sizeof(h);j++)
      printf("%02x",h[j]);
    printf("\",\n");
    printf("        \"shared_secret\": \"");
    for(j=0;j<CRYPTO_BYTES;j++)
      printf("%02x",key_b[j]);
    printf("\"\n");

    // Decapsulation
    crypto_kem_dec(key_a, ct, sk);
    for(j=0;j<CRYPTO_BYTES;j++) {
      if(key_a[j] != key_b[j]) {
        fprintf(stderr, "ERROR\n");
        return -1;
      }
    }
    printf("    }%s\n", i == NTESTS-1 ? "" : ",");
  }
  printf("]\n");
  return 0;
}
