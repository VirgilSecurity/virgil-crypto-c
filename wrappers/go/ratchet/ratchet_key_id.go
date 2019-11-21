package ratchet

// #include <virgil/crypto/ratchet/vscr_ratchet_public.h>
import "C"
import "runtime"


/*
* Utils class for working with keys formats.
*/
type RatchetKeyId struct {
    cCtx *C.vscr_ratchet_key_id_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *RatchetKeyId) ctx() *C.vscf_impl_t {
    return (*C.vscf_impl_t)(obj.cCtx)
}

func NewRatchetKeyId() *RatchetKeyId {
    ctx := C.vscr_ratchet_key_id_new()
    obj := &RatchetKeyId {
        cCtx: ctx,
    }
    //runtime.SetFinalizer(obj, func (o *RatchetKeyId) {o.Delete()})
    runtime.SetFinalizer(obj, (*RatchetKeyId).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newRatchetKeyIdWithCtx(ctx *C.vscr_ratchet_key_id_t /*ct2*/) *RatchetKeyId {
    obj := &RatchetKeyId {
        cCtx: ctx,
    }
    //runtime.SetFinalizer(obj, func (o *RatchetKeyId) {o.Delete()})
    runtime.SetFinalizer(obj, (*RatchetKeyId).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newRatchetKeyIdCopy(ctx *C.vscr_ratchet_key_id_t /*ct2*/) *RatchetKeyId {
    obj := &RatchetKeyId {
        cCtx: C.vscr_ratchet_key_id_shallow_copy(ctx),
    }
    //runtime.SetFinalizer(obj, func (o *RatchetKeyId) {o.Delete()})
    runtime.SetFinalizer(obj, (*RatchetKeyId).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *RatchetKeyId) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *RatchetKeyId) delete() {
    C.vscr_ratchet_key_id_delete(obj.cCtx)
}

/*
* Computes 8 bytes key pair id from Curve25519 (in PKCS8 or raw format) public key
*/
func (obj *RatchetKeyId) ComputePublicKeyId(publicKey []byte) ([]byte, error) {
    keyIdBuf, keyIdBufErr := bufferNewBuffer(int(RatchetCommonKeyIdLen /* lg4 */))
    if keyIdBufErr != nil {
        return nil, keyIdBufErr
    }
    defer keyIdBuf.Delete()
    publicKeyData := helperWrapData (publicKey)

    proxyResult := /*pr4*/C.vscr_ratchet_key_id_compute_public_key_id(obj.cCtx, publicKeyData, keyIdBuf.ctx)

    err := RatchetErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return keyIdBuf.getData() /* r7 */, nil
}
