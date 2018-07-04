include_guard()

option(MBEDTLS_SHA256_C "" ON)
option(MBEDTLS_SHA512_C "" ON)
option(MBEDTLS_CIPHER_C "" ON)
option(MBEDTLS_AES_C "" ON)
option(MBEDTLS_GCM_C "" ON)
option(MBEDTLS_MD_C "" ON)
option(MBEDTLS_CTR_DRBG_C "" ON)
option(MBEDTLS_ENTROPY_C "" ON)

if(MBEDTLS_CTR_DRBG_C AND NOT MBEDTLS_ENTROPY_C)
    message(FATAL_ERROR "Feature MBEDTLS_CTR_DRBG_C depends on the feature: MBEDTLS_ENTROPY_C - which is disabled.")
endif()

if(MBEDTLS_ENTROPY_C AND NOT MBEDTLS_SHA256_C AND NOT MBEDTLS_SHA512_C)
    message(FATAL_ERROR "Feature MBEDTLS_ENTROPY_C depends on one of the features: MBEDTLS_SHA256_C, MBEDTLS_SHA512_C - which are disabled.")
endif()
