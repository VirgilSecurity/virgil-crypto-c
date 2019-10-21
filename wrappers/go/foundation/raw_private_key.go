package foundation

// #cgo CFLAGS: -I${SRCDIR}/../../../build/library/foundation/include/virgil/crypto/foundation
// #cgo CFLAGS: -I${SRCDIR}/../../../library/foundation/include/virgil/crypto/foundation
// #cgo LDFLAGS: -L${SRCDIR}/../../java/binaries/linux/lib -lvscf_foundation_java
// #include <vscf_foundation_public.h>
import "C"
import . "virgil/common"

/*
* Handles interchangeable private key representation.
*/
type RawPrivateKey struct {
    IKey
    IPrivateKey
    ctx *C.vscf_impl_t
}

/*
* Return key data.
*/
func (this RawPrivateKey) Data () []byte {
    proxyResult := C.vscf_raw_private_key_data(this.ctx)

    return ExtractData(proxyResult) /* r1 */
}

/*
* Return true if private key contains public key.
*/
func (this RawPrivateKey) HasPublicKey () bool {
    proxyResult := C.vscf_raw_private_key_has_public_key(this.ctx)

    return proxyResult //r9
}

/*
* Setup public key related to the private key.
*/
func (this RawPrivateKey) SetPublicKey (rawPublicKey RawPublicKey) {
    rawPublicKeyCopy := C.vscf_raw_public_key_shallow_copy(rawPublicKey.Ctx())

    C.vscf_raw_private_key_set_public_key(this.ctx, &rawPublicKeyCopy)
}

/*
* Return public key related to the private key.
*/
func (this RawPrivateKey) GetPublicKey () RawPublicKey {
    proxyResult := C.vscf_raw_private_key_get_public_key(this.ctx)

    return RawPublicKey.init(use: proxyResult!) /* r5 */
}

/* Handle underlying C context. */
func (this RawPrivateKey) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewRawPrivateKey () *RawPrivateKey {
    ctx := C.vscf_raw_private_key_new()
    return &RawPrivateKey {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewRawPrivateKeyWithCtx (ctx *C.vscf_impl_t) *RawPrivateKey {
    return &RawPrivateKey {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewRawPrivateKeyCopy (ctx *C.vscf_impl_t) *RawPrivateKey {
    return &RawPrivateKey {
        ctx: C.vscf_raw_private_key_shallow_copy(ctx),
    }
}

/*
* Algorithm identifier the key belongs to.
*/
func (this RawPrivateKey) AlgId () AlgId {
    proxyResult := C.vscf_raw_private_key_alg_id(this.ctx)

    return AlgId(proxyResult) /* r8 */
}

/*
* Return algorithm information that can be used for serialization.
*/
func (this RawPrivateKey) AlgInfo () IAlgInfo {
    proxyResult := C.vscf_raw_private_key_alg_info(this.ctx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Length of the key in bytes.
*/
func (this RawPrivateKey) Len () int32 {
    proxyResult := C.vscf_raw_private_key_len(this.ctx)

    return proxyResult //r9
}

/*
* Length of the key in bits.
*/
func (this RawPrivateKey) Bitlen () int32 {
    proxyResult := C.vscf_raw_private_key_bitlen(this.ctx)

    return proxyResult //r9
}

/*
* Check that key is valid.
* Note, this operation can be slow.
*/
func (this RawPrivateKey) IsValid () bool {
    proxyResult := C.vscf_raw_private_key_is_valid(this.ctx)

    return proxyResult //r9
}

/*
* Extract public key from the private key.
*/
func (this RawPrivateKey) ExtractPublicKey () IPublicKey {
    proxyResult := C.vscf_raw_private_key_extract_public_key(this.ctx)

    return FoundationImplementationWrapIPublicKey(proxyResult) /* r4 */
}
