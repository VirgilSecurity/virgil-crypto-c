package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Sign data of any size.
*/
type Signer struct {
    cCtx *C.vscf_signer_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *Signer) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewSigner() *Signer {
    ctx := C.vscf_signer_new()
    obj := &Signer {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*Signer).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newSignerWithCtx(ctx *C.vscf_signer_t /*ct2*/) *Signer {
    obj := &Signer {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*Signer).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newSignerCopy(ctx *C.vscf_signer_t /*ct2*/) *Signer {
    obj := &Signer {
        cCtx: C.vscf_signer_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*Signer).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *Signer) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *Signer) delete() {
    C.vscf_signer_delete(obj.cCtx)
}

func (obj *Signer) SetHash(hash Hash) {
    C.vscf_signer_release_hash(obj.cCtx)
    C.vscf_signer_use_hash(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(hash.Ctx())))

    runtime.KeepAlive(hash)
    runtime.KeepAlive(obj)
}

func (obj *Signer) SetRandom(random Random) {
    C.vscf_signer_release_random(obj.cCtx)
    C.vscf_signer_use_random(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(random.Ctx())))

    runtime.KeepAlive(random)
    runtime.KeepAlive(obj)
}

/*
* Start a processing a new signature.
*/
func (obj *Signer) Reset() {
    C.vscf_signer_reset(obj.cCtx)

    runtime.KeepAlive(obj)

    return
}

/*
* Add given data to the signed data.
*/
func (obj *Signer) AppendData(data []byte) {
    dataData := helperWrapData (data)

    C.vscf_signer_append_data(obj.cCtx, dataData)

    runtime.KeepAlive(obj)

    return
}

/*
* Return length of the signature.
*/
func (obj *Signer) SignatureLen(privateKey PrivateKey) uint32 {
    proxyResult := /*pr4*/C.vscf_signer_signature_len(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())))

    runtime.KeepAlive(obj)

    runtime.KeepAlive(privateKey)

    return uint32(proxyResult) /* r9 */
}

/*
* Accomplish signing and return signature.
*/
func (obj *Signer) Sign(privateKey PrivateKey) ([]byte, error) {
    signatureBuf, signatureBufErr := bufferNewBuffer(int(obj.SignatureLen(privateKey.(PrivateKey)) /* lg2 */))
    if signatureBufErr != nil {
        return nil, signatureBufErr
    }
    defer signatureBuf.Delete()


    proxyResult := /*pr4*/C.vscf_signer_sign(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())), signatureBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(privateKey)

    return signatureBuf.getData() /* r7 */, nil
}
