package sdk_core

// #include <virgil/sdk/core/vssc_core_sdk_public.h>
import "C"
import unsafe "unsafe"
import "runtime"
import foundation "virgil/foundation"


/*
* Class responsible for signing "raw card".
*/
type RawCardSigner struct {
    cCtx *C.vssc_raw_card_signer_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *RawCardSigner) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewRawCardSigner() *RawCardSigner {
    ctx := C.vssc_raw_card_signer_new()
    obj := &RawCardSigner {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*RawCardSigner).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewRawCardSignerWithCtx(pointer unsafe.Pointer) *RawCardSigner {
    ctx := (*C.vssc_raw_card_signer_t /*ct2*/)(pointer)
    obj := &RawCardSigner {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*RawCardSigner).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewRawCardSignerCopy(pointer unsafe.Pointer) *RawCardSigner {
    ctx := (*C.vssc_raw_card_signer_t /*ct2*/)(pointer)
    obj := &RawCardSigner {
        cCtx: C.vssc_raw_card_signer_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*RawCardSigner).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *RawCardSigner) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *RawCardSigner) delete() {
    C.vssc_raw_card_signer_delete(obj.cCtx)
}

func (obj *RawCardSigner) SetRandom(random foundation.Random) {
    C.vssc_raw_card_signer_release_random(obj.cCtx)
    C.vssc_raw_card_signer_use_random(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(random.Ctx())))

    runtime.KeepAlive(random)
    runtime.KeepAlive(obj)
}

/*
* Adds signature to given "raw card" with provided signer and private key.
*/
func (obj *RawCardSigner) Sign(rawCard *RawCard, signerId string, privateKey foundation.PrivateKey) error {
    signerIdChar := C.CString(signerId)
    defer C.free(unsafe.Pointer(signerIdChar))
    signerIdStr := C.vsc_str_from_str(signerIdChar)

    proxyResult := /*pr4*/C.vssc_raw_card_signer_sign(obj.cCtx, (*C.vssc_raw_card_t)(unsafe.Pointer(rawCard.Ctx())), signerIdStr, (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())))

    err := CoreSdkErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(rawCard)

    runtime.KeepAlive(signerId)

    runtime.KeepAlive(privateKey)

    return nil
}

/*
* Adds self-signature to given "raw card".
*/
func (obj *RawCardSigner) SelfSign(rawCard *RawCard, privateKey foundation.PrivateKey) error {
    proxyResult := /*pr4*/C.vssc_raw_card_signer_self_sign(obj.cCtx, (*C.vssc_raw_card_t)(unsafe.Pointer(rawCard.Ctx())), (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())))

    err := CoreSdkErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(rawCard)

    runtime.KeepAlive(privateKey)

    return nil
}

/*
* Adds Virgil Signature to given "raw card".
*/
func (obj *RawCardSigner) VirgilSign(rawCard *RawCard, privateKey foundation.PrivateKey) error {
    proxyResult := /*pr4*/C.vssc_raw_card_signer_virgil_sign(obj.cCtx, (*C.vssc_raw_card_t)(unsafe.Pointer(rawCard.Ctx())), (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())))

    err := CoreSdkErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(rawCard)

    runtime.KeepAlive(privateKey)

    return nil
}
