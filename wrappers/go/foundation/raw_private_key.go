package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"


/*
* Handles interchangeable private key representation.
*/
type RawPrivateKey struct {
    IKey
    IPrivateKey
    cCtx *C.vscf_raw_private_key_t /*ct10*/
}

/*
* Return key data.
*/
func (obj *RawPrivateKey) Data () []byte {
    proxyResult := /*pr4*/C.vscf_raw_private_key_data(obj.cCtx)

    return helperExtractData(proxyResult) /* r1 */
}

/*
* Return true if private key contains public key.
*/
func (obj *RawPrivateKey) HasPublicKey () bool {
    proxyResult := /*pr4*/C.vscf_raw_private_key_has_public_key(obj.cCtx)

    return bool(proxyResult) /* r9 */
}

/*
* Setup public key related to the private key.
*/
func (obj *RawPrivateKey) SetPublicKey (rawPublicKey *RawPublicKey) {
    rawPublicKeyCopy := C.vscf_raw_public_key_shallow_copy((*C.vscf_raw_public_key_t)(rawPublicKey.ctx()))

    C.vscf_raw_private_key_set_public_key(obj.cCtx, &rawPublicKeyCopy)

    return
}

/*
* Return public key related to the private key.
*/
func (obj *RawPrivateKey) GetPublicKey () *RawPublicKey {
    proxyResult := /*pr4*/C.vscf_raw_private_key_get_public_key(obj.cCtx)

    return newRawPublicKeyWithCtx(proxyResult) /* r5 */
}

/* Handle underlying C context. */
func (obj *RawPrivateKey) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(obj.cCtx)
}

func NewRawPrivateKey () *RawPrivateKey {
    ctx := C.vscf_raw_private_key_new()
    return &RawPrivateKey {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newRawPrivateKeyWithCtx (ctx *C.vscf_raw_private_key_t /*ct10*/) *RawPrivateKey {
    return &RawPrivateKey {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newRawPrivateKeyCopy (ctx *C.vscf_raw_private_key_t /*ct10*/) *RawPrivateKey {
    return &RawPrivateKey {
        cCtx: C.vscf_raw_private_key_shallow_copy(ctx),
    }
}

/*
* Release underlying C context.
*/
func (obj *RawPrivateKey) Delete () {
    C.vscf_raw_private_key_delete(obj.cCtx)
}

/*
* Algorithm identifier the key belongs to.
*/
func (obj *RawPrivateKey) AlgId () AlgId {
    proxyResult := /*pr4*/C.vscf_raw_private_key_alg_id(obj.cCtx)

    return AlgId(proxyResult) /* r8 */
}

/*
* Return algorithm information that can be used for serialization.
*/
func (obj *RawPrivateKey) AlgInfo () (IAlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_raw_private_key_alg_info(obj.cCtx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Length of the key in bytes.
*/
func (obj *RawPrivateKey) Len () uint32 {
    proxyResult := /*pr4*/C.vscf_raw_private_key_len(obj.cCtx)

    return uint32(proxyResult) /* r9 */
}

/*
* Length of the key in bits.
*/
func (obj *RawPrivateKey) Bitlen () uint32 {
    proxyResult := /*pr4*/C.vscf_raw_private_key_bitlen(obj.cCtx)

    return uint32(proxyResult) /* r9 */
}

/*
* Check that key is valid.
* Note, this operation can be slow.
*/
func (obj *RawPrivateKey) IsValid () bool {
    proxyResult := /*pr4*/C.vscf_raw_private_key_is_valid(obj.cCtx)

    return bool(proxyResult) /* r9 */
}

/*
* Extract public key from the private key.
*/
func (obj *RawPrivateKey) ExtractPublicKey () (IPublicKey, error) {
    proxyResult := /*pr4*/C.vscf_raw_private_key_extract_public_key(obj.cCtx)

    return FoundationImplementationWrapIPublicKey(proxyResult) /* r4 */
}
