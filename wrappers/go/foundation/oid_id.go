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
    OidIdPkcs5Pbkdf2 OidId = 12
    OidIdPkcs5Pbes2 OidId = 13
    OidIdCmsData OidId = 14
    OidIdCmsEnvelopedData OidId = 15
    OidIdHkdfWithSha256 OidId = 16
    OidIdHkdfWithSha384 OidId = 17
    OidIdHkdfWithSha512 OidId = 18
    OidIdHmacWithSha224 OidId = 19
    OidIdHmacWithSha256 OidId = 20
    OidIdHmacWithSha384 OidId = 21
    OidIdHmacWithSha512 OidId = 22
    OidIdEcGenericKey OidId = 23
    OidIdEcDomainSecp256r1 OidId = 24
    OidIdCompoundKey OidId = 25
    OidIdChainedKey OidId = 26
    OidIdFalcon OidId = 27
    OidIdRound5 OidId = 28
    OidIdRound5Nd5pke5d OidId = 29
)
