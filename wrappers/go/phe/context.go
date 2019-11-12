package phe

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_phe -lvsc_phe_pb -lvsc_foundation -lvsc_foundation_pb -led25519 -lprotobuf-nanopb -lvsc_common -lmbedcrypto
// #include <virgil/crypto/phe/vsce_phe_public.h>
import "C"

type context interface {

    /* Get C context */
    ctx () *C.vscf_impl_t
}

