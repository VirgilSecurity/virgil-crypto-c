/*
 * Configuration header for mldsa-native v1.0.0-beta — ML-DSA-65 parameter set.
 *
 * Injected into the mldsa-native source tree at build time.
 * MLD_CONFIG_NO_RANDOMIZED_API removes all randomized functions and the
 * randombytes dependency entirely; only *_internal API remains.
 */

#ifndef MLDSA_CONFIG_65_H
#define MLDSA_CONFIG_65_H

#define MLD_CONFIG_PARAMETER_SET 65
#define MLD_CONFIG_NAMESPACE_PREFIX mldsa65
#define MLD_CONFIG_NO_RANDOMIZED_API

#endif /* MLDSA_CONFIG_65_H */
