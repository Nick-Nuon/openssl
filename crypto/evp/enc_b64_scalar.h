#ifndef OSSL_CRYPTO_EVP_B64_SCALAR_H
# define OSSL_CRYPTO_EVP_B64_SCALAR_H
#include <openssl/evp.h>

#if defined(__x86_64) || defined(__x86_64__) || \
     defined(_M_AMD64) || defined (_M_X64)
int evp_encodeblock_int(EVP_ENCODE_CTX *ctx, unsigned char *t,
                        const unsigned char *f, int dlen, int *wrap_cnt);
#endif

#endif
