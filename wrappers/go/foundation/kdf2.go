package foundation

// #cgo CFLAGS: -I${SRCDIR}/../../../build/library/foundation/include/virgil/crypto/foundation
// #cgo CFLAGS: -I${SRCDIR}/../../../library/foundation/include/virgil/crypto/foundation
// #cgo LDFLAGS: -L${SRCDIR}/../../java/binaries/linux/lib -lvscf_foundation_java
// #include <vscf_foundation_public.h>
import "C"
import . "virgil/common"

/*
* Virgil Security implementation of the KDF2 (ISO-18033-2) algorithm.
*/
type Kdf2 struct {
    IAlg
    IKdf
    ctx *C.vscf_impl_t
}

func (this Kdf2) SetHash (hash IHash) {
    C.vscf_kdf2_release_hash(this.ctx)
    C.vscf_kdf2_use_hash(this.ctx, hash.Ctx())
}

/* Handle underlying C context. */
func (this Kdf2) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewKdf2 () *Kdf2 {
    ctx := C.vscf_kdf2_new()
    return &Kdf2 {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewKdf2WithCtx (ctx *C.vscf_impl_t) *Kdf2 {
    return &Kdf2 {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewKdf2Copy (ctx *C.vscf_impl_t) *Kdf2 {
    return &Kdf2 {
        ctx: C.vscf_kdf2_shallow_copy(ctx),
    }
}

/*
* Provide algorithm identificator.
*/
func (this Kdf2) AlgId () AlgId {
    proxyResult := C.vscf_kdf2_alg_id(this.ctx)

    return AlgId(proxyResult) /* r8 */
}

/*
* Produce object with algorithm information and configuration parameters.
*/
func (this Kdf2) ProduceAlgInfo () IAlgInfo {
    proxyResult := C.vscf_kdf2_produce_alg_info(this.ctx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Restore algorithm configuration from the given object.
*/
func (this Kdf2) RestoreAlgInfo (algInfo IAlgInfo) {
    proxyResult := C.vscf_kdf2_restore_alg_info(this.ctx, algInfo.Ctx())

    FoundationErrorHandleStatus(proxyResult)
}

/*
* Derive key of the requested length from the given data.
*/
func (this Kdf2) Derive (data []byte, keyLen int32) []byte {
    keyCount := keyLen
    keyBuf := NewBuffer(keyCount)
    defer keyBuf.Clear()


    C.vscf_kdf2_derive(this.ctx, WrapData(data), keyLen, keyBuf)

    return keyBuf.GetData() /* r7 */
}
