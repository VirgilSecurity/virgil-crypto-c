package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"

type context interface {

    /* Get C context */
    ctx () *C.vscf_impl_t
}

