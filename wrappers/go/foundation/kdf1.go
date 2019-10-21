package foundation

// #cgo CFLAGS: -I${SRCDIR}/../../../build/library/foundation/include/virgil/crypto/foundation
// #cgo CFLAGS: -I${SRCDIR}/../../../library/foundation/include/virgil/crypto/foundation
// #cgo LDFLAGS: -L${SRCDIR}/../../java/binaries/linux/lib -lvscf_foundation_java
// #include <vscf_foundation_public.h>
import "C"
import . "virgil/common"

/*
* Virgil Security implementation of the KDF1 (ISO-18033-2) algorithm.
*/
type Kdf1 struct {
    IAlg
    IKdf
    ctx *C.vscf_impl_t
}

func (this Kdf1) SetHash (hash IHash) {
    C.vscf_kdf1_release_hash(this.ctx)
    C.vscf_kdf1_use_hash(this.ctx, hash.Ctx())
}

/* Handle underlying C context. */
func (this Kdf1) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewKdf1 () *Kdf1 {
    ctx := C.vscf_kdf1_new()
    return &Kdf1 {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewKdf1WithCtx (ctx *C.vscf_impl_t) *Kdf1 {
    return &Kdf1 {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewKdf1Copy (ctx *C.vscf_impl_t) *Kdf1 {
    return &Kdf1 {
        ctx: C.vscf_kdf1_shallow_copy(ctx),
    }
}

/*
* Provide algorithm identificator.
*/
func (this Kdf1) AlgId () AlgId {
    proxyResult := C.vscf_kdf1_alg_id(this.ctx)

    return AlgId(proxyResult) /* r8 */
}

/*
* Produce object with algorithm information and configuration parameters.
*/
func (this Kdf1) ProduceAlgInfo () IAlgInfo {
    proxyResult := C.vscf_kdf1_produce_alg_info(this.ctx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Restore algorithm configuration from the given object.
*/
func (this Kdf1) RestoreAlgInfo (algInfo IAlgInfo) {
    proxyResult := C.vscf_kdf1_restore_alg_info(this.ctx, algInfo.Ctx())

    FoundationErrorHandleStatus(proxyResult)
}

/*
* Derive key of the requested length from the given data.
*/
func (this Kdf1) Derive (data []byte, keyLen int32) []byte {
    keyCount := keyLen
    keyBuf := NewBuffer(keyCount)
    defer keyBuf.Clear()


    C.vscf_kdf1_derive(this.ctx, WrapData(data), keyLen, keyBuf)

    return keyBuf.GetData() /* r7 */
}
