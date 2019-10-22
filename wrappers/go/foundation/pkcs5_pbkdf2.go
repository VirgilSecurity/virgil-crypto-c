package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_common
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_foundation
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import . "virgil/common"

/*
* Virgil Security implementation of the PBKDF2 (RFC 8018) algorithm.
*/
type Pkcs5Pbkdf2 struct {
    IAlg
    IKdf
    ISaltedKdf
    ctx *C.vscf_impl_t
}

func (this Pkcs5Pbkdf2) SetHmac (hmac IMac) {
    C.vscf_pkcs5_pbkdf2_release_hmac(this.ctx)
    C.vscf_pkcs5_pbkdf2_use_hmac(this.ctx, hmac.Ctx())
}

/*
* Setup predefined values to the uninitialized class dependencies.
*/
func (this Pkcs5Pbkdf2) SetupDefaults () {
    C.vscf_pkcs5_pbkdf2_setup_defaults(this.ctx)
}

/* Handle underlying C context. */
func (this Pkcs5Pbkdf2) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewPkcs5Pbkdf2 () *Pkcs5Pbkdf2 {
    ctx := C.vscf_pkcs5_pbkdf2_new()
    return &Pkcs5Pbkdf2 {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewPkcs5Pbkdf2WithCtx (ctx *C.vscf_impl_t) *Pkcs5Pbkdf2 {
    return &Pkcs5Pbkdf2 {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewPkcs5Pbkdf2Copy (ctx *C.vscf_impl_t) *Pkcs5Pbkdf2 {
    return &Pkcs5Pbkdf2 {
        ctx: C.vscf_pkcs5_pbkdf2_shallow_copy(ctx),
    }
}

/*
* Provide algorithm identificator.
*/
func (this Pkcs5Pbkdf2) AlgId () AlgId {
    proxyResult := C.vscf_pkcs5_pbkdf2_alg_id(this.ctx)

    return AlgId(proxyResult) /* r8 */
}

/*
* Produce object with algorithm information and configuration parameters.
*/
func (this Pkcs5Pbkdf2) ProduceAlgInfo () IAlgInfo {
    proxyResult := C.vscf_pkcs5_pbkdf2_produce_alg_info(this.ctx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Restore algorithm configuration from the given object.
*/
func (this Pkcs5Pbkdf2) RestoreAlgInfo (algInfo IAlgInfo) {
    proxyResult := C.vscf_pkcs5_pbkdf2_restore_alg_info(this.ctx, algInfo.Ctx())

    FoundationErrorHandleStatus(proxyResult)
}

/*
* Derive key of the requested length from the given data.
*/
func (this Pkcs5Pbkdf2) Derive (data []byte, keyLen int32) []byte {
    keyCount := keyLen
    keyBuf := NewBuffer(keyCount)
    defer keyBuf.Clear()


    C.vscf_pkcs5_pbkdf2_derive(this.ctx, WrapData(data), keyLen, keyBuf)

    return keyBuf.GetData() /* r7 */
}

/*
* Prepare algorithm to derive new key.
*/
func (this Pkcs5Pbkdf2) Reset (salt []byte, iterationCount int32) {
    C.vscf_pkcs5_pbkdf2_reset(this.ctx, WrapData(salt), iterationCount)
}

/*
* Setup application specific information (optional).
* Can be empty.
*/
func (this Pkcs5Pbkdf2) SetInfo (info []byte) {
    C.vscf_pkcs5_pbkdf2_set_info(this.ctx, WrapData(info))
}
