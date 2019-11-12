package phe

// #include <virgil/crypto/phe/vsce_phe_public.h>
import "C"

type context interface {

    /* Get C context */
    ctx () *C.vscf_impl_t
}

