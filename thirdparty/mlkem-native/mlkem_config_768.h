/*
 * Configuration header for mlkem-native v1.0.0 — ML-KEM-768 parameter set.
 *
 * Injected into the mlkem-native source tree at build time.
 * Only the deterministic (derand) API is used; mlk_randombytes is a no-op stub.
 */

#ifndef MLKEM_CONFIG_768_H
#define MLKEM_CONFIG_768_H

#define MLK_CONFIG_PARAMETER_SET 768
#define MLK_CONFIG_NAMESPACE_PREFIX mlkem768

/* Disable OS-RNG — the wrapper uses only the derand API. */
#define MLK_CONFIG_CUSTOM_RANDOMBYTES
#ifndef __ASSEMBLER__
#include <stddef.h>
static inline void mlk_randombytes(unsigned char *p, size_t n) {
    (void)p;
    (void)n;
}
#endif /* __ASSEMBLER__ */

#endif /* MLKEM_CONFIG_768_H */
