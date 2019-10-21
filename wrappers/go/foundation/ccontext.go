package foundation

import "C"

type CContext interface {

    /* Get C context */
    Ctx () *C.vscf_impl_t
}

