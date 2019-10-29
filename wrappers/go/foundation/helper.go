package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"

type helper struct {
}

func helperDataToBytes (data C.vsc_data_t) []byte {
    return []byte("Go")
}

func helperBytesToBytePtr (data []byte) *C.uint8_t {
    return (*C.uint8_t)(&data[0])
}
