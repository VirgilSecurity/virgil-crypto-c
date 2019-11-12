package ratchet

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_ratchet -lvsc_ratchet_pb -lvsc_foundation -lvsc_foundation_pb -led25519 -lprotobuf-nanopb -lvsc_common -lmbedcrypto
// #include <virgil/crypto/ratchet/vscr_ratchet_public.h>
import "C"


type RatchetImplementation struct {
}
