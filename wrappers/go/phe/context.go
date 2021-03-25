package phe

// #include <virgil/crypto/phe/vsce_phe_public.h>
import "C"

type context interface {

    /* Get C context */
    Ctx () uintptr
}

