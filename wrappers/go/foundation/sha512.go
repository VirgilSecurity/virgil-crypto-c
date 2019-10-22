package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_common
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_foundation
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import . "virgil/common"

/*
* This is MbedTLS implementation of SHA512.
*/
type Sha512 struct {
    IAlg
    IHash
    ctx *C.vscf_impl_t
}

/* Handle underlying C context. */
func (this Sha512) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewSha512 () *Sha512 {
    ctx := C.vscf_sha512_new()
    return &Sha512 {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewSha512WithCtx (ctx *C.vscf_impl_t) *Sha512 {
    return &Sha512 {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewSha512Copy (ctx *C.vscf_impl_t) *Sha512 {
    return &Sha512 {
        ctx: C.vscf_sha512_shallow_copy(ctx),
    }
}

/*
* Provide algorithm identificator.
*/
func (this Sha512) AlgId () AlgId {
    proxyResult := C.vscf_sha512_alg_id(this.ctx)

    return AlgId(proxyResult) /* r8 */
}

/*
* Produce object with algorithm information and configuration parameters.
*/
func (this Sha512) ProduceAlgInfo () IAlgInfo {
    proxyResult := C.vscf_sha512_produce_alg_info(this.ctx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Restore algorithm configuration from the given object.
*/
func (this Sha512) RestoreAlgInfo (algInfo IAlgInfo) {
    proxyResult := C.vscf_sha512_restore_alg_info(this.ctx, algInfo.Ctx())

    FoundationErrorHandleStatus(proxyResult)
}

/*
* Length of the digest (hashing output) in bytes.
*/
func (this Sha512) getDigestLen () int32 {
    return 64
}

/*
* Block length of the digest function in bytes.
*/
func (this Sha512) getBlockLen () int32 {
    return 128
}

/*
* Calculate hash over given data.
*/
func (this Sha512) Hash (data []byte) []byte {
    digestCount := this.getDigestLen() /* lg3 */
    digestBuf := NewBuffer(digestCount)
    defer digestBuf.Clear()


    C.vscf_sha512_hash(WrapData(data), digestBuf)

    return digestBuf.GetData() /* r7 */
}

/*
* Start a new hashing.
*/
func (this Sha512) Start () {
    C.vscf_sha512_start(this.ctx)
}

/*
* Add given data to the hash.
*/
func (this Sha512) Update (data []byte) {
    C.vscf_sha512_update(this.ctx, WrapData(data))
}

/*
* Accompilsh hashing and return it's result (a message digest).
*/
func (this Sha512) Finish () []byte {
    digestCount := this.getDigestLen() /* lg3 */
    digestBuf := NewBuffer(digestCount)
    defer digestBuf.Clear()


    C.vscf_sha512_finish(this.ctx, digestBuf)

    return digestBuf.GetData() /* r7 */
}
