package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"

/*
* Handles RSA private key.
*/
type RsaPrivateKey struct {
    IKey
    IPrivateKey
    cCtx *C.vscf_rsa_private_key_t /*ct10*/
}

/* Handle underlying C context. */
func (this RsaPrivateKey) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(this.cCtx)
}

func NewRsaPrivateKey () *RsaPrivateKey {
    ctx := C.vscf_rsa_private_key_new()
    return &RsaPrivateKey {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newRsaPrivateKeyWithCtx (ctx *C.vscf_rsa_private_key_t /*ct10*/) *RsaPrivateKey {
    return &RsaPrivateKey {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newRsaPrivateKeyCopy (ctx *C.vscf_rsa_private_key_t /*ct10*/) *RsaPrivateKey {
    return &RsaPrivateKey {
        cCtx: C.vscf_rsa_private_key_shallow_copy(ctx),
    }
}

/// Release underlying C context.
func (this RsaPrivateKey) close () {
    C.vscf_rsa_private_key_delete(this.cCtx)
}

/*
* Algorithm identifier the key belongs to.
*/
func (this RsaPrivateKey) AlgId () AlgId {
    proxyResult := /*pr4*/C.vscf_rsa_private_key_alg_id(this.cCtx)

    return AlgId(proxyResult) /* r8 */
}

/*
* Return algorithm information that can be used for serialization.
*/
func (this RsaPrivateKey) AlgInfo () (IAlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_rsa_private_key_alg_info(this.cCtx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Length of the key in bytes.
*/
func (this RsaPrivateKey) Len () uint32 {
    proxyResult := /*pr4*/C.vscf_rsa_private_key_len(this.cCtx)

    return uint32(proxyResult) /* r9 */
}

/*
* Length of the key in bits.
*/
func (this RsaPrivateKey) Bitlen () uint32 {
    proxyResult := /*pr4*/C.vscf_rsa_private_key_bitlen(this.cCtx)

    return uint32(proxyResult) /* r9 */
}

/*
* Check that key is valid.
* Note, this operation can be slow.
*/
func (this RsaPrivateKey) IsValid () bool {
    proxyResult := /*pr4*/C.vscf_rsa_private_key_is_valid(this.cCtx)

    return bool(proxyResult) /* r9 */
}

/*
* Extract public key from the private key.
*/
func (this RsaPrivateKey) ExtractPublicKey () (IPublicKey, error) {
    proxyResult := /*pr4*/C.vscf_rsa_private_key_extract_public_key(this.cCtx)

    return FoundationImplementationWrapIPublicKey(proxyResult) /* r4 */
}
