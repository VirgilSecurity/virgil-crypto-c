package phe

// #include <virgil/crypto/phe/vsce_phe_public.h>
import "C"


type PheCommon struct {
}
const (
    PheCommonPhePointLength uint = 65
    PheCommonPheMaxPasswordLength uint = 128
    PheCommonPheServerIdentifierLength uint = 32
    PheCommonPheClientIdentifierLength uint = 32
    PheCommonPheAccountKeyLength uint = 32
    PheCommonPhePrivateKeyLength uint = 32
    PheCommonPhePublicKeyLength uint = 65
    PheCommonPheHashLen uint = 32
    PheCommonPheMaxEncryptLen uint = 1024 * 1024 - 64
    PheCommonPheMaxDecryptLen uint = 1024 * 1024
    PheCommonPheMaxAuthLen uint = 1024
)
