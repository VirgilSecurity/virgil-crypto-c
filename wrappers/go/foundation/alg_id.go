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
    AlgIdEcc AlgId = 8
    AlgIdEd25519 AlgId = 9
    AlgIdCurve25519 AlgId = 10
    AlgIdSecp256r1 AlgId = 11
    AlgIdAes256Gcm AlgId = 12
    AlgIdAes256Cbc AlgId = 13
    AlgIdHmac AlgId = 14
    AlgIdHkdf AlgId = 15
    AlgIdPkcs5Pbkdf2 AlgId = 16
    AlgIdPkcs5Pbes2 AlgId = 17
)
