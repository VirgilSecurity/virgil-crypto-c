package sdk_core

// #include <virgil/sdk/core/vssc_core_sdk_public.h>
import "C"

type context interface {

    /* Get C context */
    Ctx () uintptr
}

