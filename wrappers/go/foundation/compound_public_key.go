package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import "runtime"
import unsafe "unsafe"


/*
* Handles compound public key.
*
* Compound public key contains 2 public keys and signature:
* - cipher key - is used for encryption;
* - signer key - is used for verifying;
* - signature - signature of the "cipher public key".
*/
type CompoundPublicKey struct {
    cCtx *C.vscf_compound_public_key_t /*ct10*/
}

/*
* Return a cipher public key suitable for initial encryption.
*/
func (obj *CompoundPublicKey) CipherKey() (PublicKey, error) {
    proxyResult := /*pr4*/C.vscf_compound_public_key_cipher_key(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapPublicKey(proxyResult) /* r4 */
}

/*
* Return public key suitable for verifying.
*/
func (obj *CompoundPublicKey) SignerKey() (PublicKey, error) {
    proxyResult := /*pr4*/C.vscf_compound_public_key_signer_key(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapPublicKey(proxyResult) /* r4 */
}

/*
* Return cipher public key signature.
*/
func (obj *CompoundPublicKey) Signature() []byte {
    proxyResult := /*pr4*/C.vscf_compound_public_key_signature(obj.cCtx)

    runtime.KeepAlive(obj)

    return helperExtractData(proxyResult) /* r1 */
}

/* Handle underlying C context. */
func (obj *CompoundPublicKey) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewCompoundPublicKey() *CompoundPublicKey {
    ctx := C.vscf_compound_public_key_new()
    obj := &CompoundPublicKey {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*CompoundPublicKey).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newCompoundPublicKeyWithCtx(ctx *C.vscf_compound_public_key_t /*ct10*/) *CompoundPublicKey {
    obj := &CompoundPublicKey {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*CompoundPublicKey).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newCompoundPublicKeyCopy(ctx *C.vscf_compound_public_key_t /*ct10*/) *CompoundPublicKey {
    obj := &CompoundPublicKey {
        cCtx: C.vscf_compound_public_key_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*CompoundPublicKey).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *CompoundPublicKey) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *CompoundPublicKey) delete() {
    C.vscf_compound_public_key_delete(obj.cCtx)
}

/*
* Algorithm identifier the key belongs to.
*/
func (obj *CompoundPublicKey) AlgId() AlgId {
    proxyResult := /*pr4*/C.vscf_compound_public_key_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult) /* r8 */
}

/*
* Return algorithm information that can be used for serialization.
*/
func (obj *CompoundPublicKey) AlgInfo() (AlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_compound_public_key_alg_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapAlgInfo(proxyResult) /* r4 */
}

/*
* Length of the key in bytes.
*/
func (obj *CompoundPublicKey) Len() uint32 {
    proxyResult := /*pr4*/C.vscf_compound_public_key_len(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint32(proxyResult) /* r9 */
}

/*
* Length of the key in bits.
*/
func (obj *CompoundPublicKey) Bitlen() uint32 {
    proxyResult := /*pr4*/C.vscf_compound_public_key_bitlen(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint32(proxyResult) /* r9 */
}

/*
* Check that key is valid.
* Note, this operation can be slow.
*/
func (obj *CompoundPublicKey) IsValid() bool {
    proxyResult := /*pr4*/C.vscf_compound_public_key_is_valid(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}
