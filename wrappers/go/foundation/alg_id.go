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
    AlgIdHmac AlgId = 13
    AlgIdHkdf AlgId = 14
    AlgIdPkcs5Pbkdf2 AlgId = 15
    AlgIdPkcs5Pbes2 AlgId = 16
    AlgIdCompoundKey AlgId = 17
    AlgIdHybridKey AlgId = 18
    AlgIdFalcon AlgId = 19
    AlgIdRound5Nd1cca5d AlgId = 20
    AlgIdRandomPadding AlgId = 21
)
