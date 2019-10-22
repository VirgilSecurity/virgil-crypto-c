package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_common
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_foundation
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import . "virgil/common"

/*
* Virgil Security implementation of the HKDF (RFC 6234) algorithm.
*/
type Hkdf struct {
    IAlg
    IKdf
    ISaltedKdf
    ctx *C.vscf_impl_t
}

func (this Hkdf) getHashCounterMax () int32 {
    return 255
}

func (this Hkdf) SetHash (hash IHash) {
    C.vscf_hkdf_release_hash(this.ctx)
    C.vscf_hkdf_use_hash(this.ctx, hash.Ctx())
}

/* Handle underlying C context. */
func (this Hkdf) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewHkdf () *Hkdf {
    ctx := C.vscf_hkdf_new()
    return &Hkdf {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewHkdfWithCtx (ctx *C.vscf_impl_t) *Hkdf {
    return &Hkdf {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewHkdfCopy (ctx *C.vscf_impl_t) *Hkdf {
    return &Hkdf {
        ctx: C.vscf_hkdf_shallow_copy(ctx),
    }
}

/*
* Provide algorithm identificator.
*/
func (this Hkdf) AlgId () AlgId {
    proxyResult := C.vscf_hkdf_alg_id(this.ctx)

    return AlgId(proxyResult) /* r8 */
}

/*
* Produce object with algorithm information and configuration parameters.
*/
func (this Hkdf) ProduceAlgInfo () IAlgInfo {
    proxyResult := C.vscf_hkdf_produce_alg_info(this.ctx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Restore algorithm configuration from the given object.
*/
func (this Hkdf) RestoreAlgInfo (algInfo IAlgInfo) {
    proxyResult := C.vscf_hkdf_restore_alg_info(this.ctx, algInfo.Ctx())

    FoundationErrorHandleStatus(proxyResult)
}

/*
* Derive key of the requested length from the given data.
*/
func (this Hkdf) Derive (data []byte, keyLen int32) []byte {
    keyCount := keyLen
    keyBuf := NewBuffer(keyCount)
    defer keyBuf.Clear()


    C.vscf_hkdf_derive(this.ctx, WrapData(data), keyLen, keyBuf)

    return keyBuf.GetData() /* r7 */
}

/*
* Prepare algorithm to derive new key.
*/
func (this Hkdf) Reset (salt []byte, iterationCount int32) {
    C.vscf_hkdf_reset(this.ctx, WrapData(salt), iterationCount)
}

/*
* Setup application specific information (optional).
* Can be empty.
*/
func (this Hkdf) SetInfo (info []byte) {
    C.vscf_hkdf_set_info(this.ctx, WrapData(info))
}
