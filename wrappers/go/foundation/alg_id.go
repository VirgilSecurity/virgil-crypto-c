package foundation

import "C"

/*
* Define implemented algorithm identificator.
*/
type AlgId int
const (
    AlgIdNone AlgId = 0
    AlgIdSha224 AlgId = 1
    AlgIdSha256 AlgId = 2
    AlgIdSha384 AlgId = 3
    AlgIdSha512 AlgId = 4
    AlgIdKdf1 AlgId = 5
    AlgIdKdf2 AlgId = 6
    AlgIdRsa AlgId = 7
    AlgIdEd25519 AlgId = 8
    AlgIdCurve25519 AlgId = 9
    AlgIdSecp256r1 AlgId = 10
    AlgIdAes256Gcm AlgId = 11
    AlgIdAes256Cbc AlgId = 12
    AlgIdAes128Kw AlgId = 13
    AlgIdAes192Kw AlgId = 14
    AlgIdAes256Kw AlgId = 15
    AlgIdHmac AlgId = 16
    AlgIdHkdf AlgId = 17
    AlgIdPkcs5Pbkdf2 AlgId = 18
    AlgIdPkcs5Pbes2 AlgId = 19
    AlgIdCompoundKey AlgId = 20
    AlgIdHybridKey AlgId = 21
    AlgIdFalcon AlgId = 22
    AlgIdRandomPadding AlgId = 23
    AlgIdMlKem768 AlgId = 24
    AlgIdMlDsa65 AlgId = 25
    AlgIdAes256GcmChunked AlgId = 26
)
