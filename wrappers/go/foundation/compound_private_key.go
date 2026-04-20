package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Handles compound private key.
*
* Compound private key contains 2 private keys and signature:
*     - cipher key - is used for decryption;
*     - signer key - is used for signing.
*/
type CompoundPrivateKey struct {
    cCtx *C.vscf_compound_private_key_t
}

/*
* Return primary private key suitable for a final decryption.
*/
func (obj *CompoundPrivateKey) CipherKey() (PrivateKey, error) {
    proxyResult := C.vscf_compound_private_key_cipher_key(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapPrivateKeyCopy(proxyResult)
}

/*
* Return private key suitable for signing.
*/
func (obj *CompoundPrivateKey) SignerKey() (PrivateKey, error) {
    proxyResult := C.vscf_compound_private_key_signer_key(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapPrivateKeyCopy(proxyResult)
}

/* Handle underlying C context. */
func (obj *CompoundPrivateKey) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewCompoundPrivateKey() *CompoundPrivateKey {
    ctx := C.vscf_compound_private_key_new()
    obj := &CompoundPrivateKey {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*CompoundPrivateKey).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newCompoundPrivateKeyWithCtx(ctx *C.vscf_compound_private_key_t) *CompoundPrivateKey {
    obj := &CompoundPrivateKey {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*CompoundPrivateKey).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newCompoundPrivateKeyCopy(ctx *C.vscf_compound_private_key_t) *CompoundPrivateKey {
    obj := &CompoundPrivateKey {
        cCtx: C.vscf_compound_private_key_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*CompoundPrivateKey).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *CompoundPrivateKey) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *CompoundPrivateKey) delete() {
    C.vscf_compound_private_key_delete(obj.cCtx)
}

/*
* Algorithm identifier the key belongs to.
*/
func (obj *CompoundPrivateKey) AlgId() AlgId {
    proxyResult := C.vscf_compound_private_key_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult)
}

/*
* Return algorithm information that can be used for serialization.
*/
func (obj *CompoundPrivateKey) AlgInfo() (AlgInfo, error) {
    proxyResult := C.vscf_compound_private_key_alg_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapAlgInfoCopy(proxyResult)
}

/*
* Length of the key in bytes.
*/
func (obj *CompoundPrivateKey) Len() uint {
    proxyResult := C.vscf_compound_private_key_len(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint(proxyResult)
}

/*
* Length of the key in bits.
*/
func (obj *CompoundPrivateKey) Bitlen() uint {
    proxyResult := C.vscf_compound_private_key_bitlen(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint(proxyResult)
}

/*
* Check that key is valid.
* Note, this operation can be slow.
*/
func (obj *CompoundPrivateKey) IsValid() bool {
    proxyResult := C.vscf_compound_private_key_is_valid(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult)
}

/*
* Extract public key from the private key.
*/
func (obj *CompoundPrivateKey) ExtractPublicKey() (PublicKey, error) {
    proxyResult := C.vscf_compound_private_key_extract_public_key(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapPublicKey(proxyResult)
}
