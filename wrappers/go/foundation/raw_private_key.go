package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
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
func (this RawPrivateKey) Data () []byte {
    proxyResult := /*pr4*/C.vscf_raw_private_key_data(this.cCtx)

    return helperExtractData(proxyResult) /* r1 */
}

/*
* Return true if private key contains public key.
*/
func (this RawPrivateKey) HasPublicKey () bool {
    proxyResult := /*pr4*/C.vscf_raw_private_key_has_public_key(this.cCtx)

    return bool(proxyResult) /* r9 */
}

/*
* Setup public key related to the private key.
*/
func (this RawPrivateKey) SetPublicKey (rawPublicKey *RawPublicKey) {
    rawPublicKeyCopy := C.vscf_raw_public_key_shallow_copy((*C.vscf_raw_public_key_t)(rawPublicKey.ctx()))

    C.vscf_raw_private_key_set_public_key(this.cCtx, &rawPublicKeyCopy)

    return
}

/*
* Return public key related to the private key.
*/
func (this RawPrivateKey) GetPublicKey () *RawPublicKey {
    proxyResult := /*pr4*/C.vscf_raw_private_key_get_public_key(this.cCtx)

    return newRawPublicKeyWithCtx(proxyResult) /* r5 */
}

/* Handle underlying C context. */
func (this RawPrivateKey) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(this.cCtx)
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

/// Release underlying C context.
func (this RawPrivateKey) clear () {
    C.vscf_raw_private_key_delete(this.cCtx)
}

/*
* Algorithm identifier the key belongs to.
*/
func (this RawPrivateKey) AlgId () AlgId {
    proxyResult := /*pr4*/C.vscf_raw_private_key_alg_id(this.cCtx)

    return AlgId(proxyResult) /* r8 */
}

/*
* Return algorithm information that can be used for serialization.
*/
func (this RawPrivateKey) AlgInfo () (IAlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_raw_private_key_alg_info(this.cCtx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Length of the key in bytes.
*/
func (this RawPrivateKey) Len () uint32 {
    proxyResult := /*pr4*/C.vscf_raw_private_key_len(this.cCtx)

    return uint32(proxyResult) /* r9 */
}

/*
* Length of the key in bits.
*/
func (this RawPrivateKey) Bitlen () uint32 {
    proxyResult := /*pr4*/C.vscf_raw_private_key_bitlen(this.cCtx)

    return uint32(proxyResult) /* r9 */
}

/*
* Check that key is valid.
* Note, this operation can be slow.
*/
func (this RawPrivateKey) IsValid () bool {
    proxyResult := /*pr4*/C.vscf_raw_private_key_is_valid(this.cCtx)

    return bool(proxyResult) /* r9 */
}

/*
* Extract public key from the private key.
*/
func (this RawPrivateKey) ExtractPublicKey () (IPublicKey, error) {
    proxyResult := /*pr4*/C.vscf_raw_private_key_extract_public_key(this.cCtx)

    return FoundationImplementationWrapIPublicKey(proxyResult) /* r4 */
}
