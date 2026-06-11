package foundation

import "C"

type OidId int
const (
    OidIdNone OidId = 0
    OidIdRsa OidId = 1
    OidIdEd25519 OidId = 2
    OidIdCurve25519 OidId = 3
    OidIdSha224 OidId = 4
    OidIdSha256 OidId = 5
    OidIdSha384 OidId = 6
    OidIdSha512 OidId = 7
    OidIdKdf1 OidId = 8
    OidIdKdf2 OidId = 9
    OidIdAes256Gcm OidId = 10
    OidIdAes256Cbc OidId = 11
    OidIdAes128Kw OidId = 12
    OidIdAes192Kw OidId = 13
    OidIdAes256Kw OidId = 14
    OidIdPkcs5Pbkdf2 OidId = 15
    OidIdPkcs5Pbes2 OidId = 16
    OidIdCmsData OidId = 17
    OidIdCmsEnvelopedData OidId = 18
    OidIdHkdfWithSha256 OidId = 19
    OidIdHkdfWithSha384 OidId = 20
    OidIdHkdfWithSha512 OidId = 21
    OidIdHmacWithSha224 OidId = 22
    OidIdHmacWithSha256 OidId = 23
    OidIdHmacWithSha384 OidId = 24
    OidIdHmacWithSha512 OidId = 25
    OidIdEcGenericKey OidId = 26
    OidIdEcDomainSecp256r1 OidId = 27
    OidIdCompoundKey OidId = 28
    OidIdHybridKey OidId = 29
    OidIdFalcon OidId = 30
    OidIdRandomPadding OidId = 31
    OidIdMlKem768 OidId = 32
    OidIdMlDsa65 OidId = 33
)
