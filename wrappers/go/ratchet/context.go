package ratchet

// #include <virgil/crypto/ratchet/vscr_ratchet_public.h>
import "C"

type context interface {

    /* Get C context */
    Ctx () uintptr
}

