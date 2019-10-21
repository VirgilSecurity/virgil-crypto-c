package foundation

// #cgo CFLAGS: -I${SRCDIR}/../../../build/library/foundation/include/virgil/crypto/foundation
// #cgo CFLAGS: -I${SRCDIR}/../../../library/foundation/include/virgil/crypto/foundation
// #cgo LDFLAGS: -L${SRCDIR}/../../java/binaries/linux/lib -lvscf_foundation_java
// #include <vscf_foundation_public.h>
import "C"
import . "virgil/common"

/*
* This is MbedTLS implementation of SHA384.
*/
type Sha384 struct {
    IAlg
    IHash
    ctx *C.vscf_impl_t
}

/* Handle underlying C context. */
func (this Sha384) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewSha384 () *Sha384 {
    ctx := C.vscf_sha384_new()
    return &Sha384 {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewSha384WithCtx (ctx *C.vscf_impl_t) *Sha384 {
    return &Sha384 {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewSha384Copy (ctx *C.vscf_impl_t) *Sha384 {
    return &Sha384 {
        ctx: C.vscf_sha384_shallow_copy(ctx),
    }
}

/*
* Provide algorithm identificator.
*/
func (this Sha384) AlgId () AlgId {
    proxyResult := C.vscf_sha384_alg_id(this.ctx)

    return AlgId(proxyResult) /* r8 */
}

/*
* Produce object with algorithm information and configuration parameters.
*/
func (this Sha384) ProduceAlgInfo () IAlgInfo {
    proxyResult := C.vscf_sha384_produce_alg_info(this.ctx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Restore algorithm configuration from the given object.
*/
func (this Sha384) RestoreAlgInfo (algInfo IAlgInfo) {
    proxyResult := C.vscf_sha384_restore_alg_info(this.ctx, algInfo.Ctx())

    FoundationErrorHandleStatus(proxyResult)
}

/*
* Length of the digest (hashing output) in bytes.
*/
func (this Sha384) getDigestLen () int32 {
    return 48
}

/*
* Block length of the digest function in bytes.
*/
func (this Sha384) getBlockLen () int32 {
    return 128
}

/*
* Calculate hash over given data.
*/
func (this Sha384) Hash (data []byte) []byte {
    digestCount := this.getDigestLen() /* lg3 */
    digestBuf := NewBuffer(digestCount)
    defer digestBuf.Clear()


    C.vscf_sha384_hash(WrapData(data), digestBuf)

    return digestBuf.GetData() /* r7 */
}

/*
* Start a new hashing.
*/
func (this Sha384) Start () {
    C.vscf_sha384_start(this.ctx)
}

/*
* Add given data to the hash.
*/
func (this Sha384) Update (data []byte) {
    C.vscf_sha384_update(this.ctx, WrapData(data))
}

/*
* Accompilsh hashing and return it's result (a message digest).
*/
func (this Sha384) Finish () []byte {
    digestCount := this.getDigestLen() /* lg3 */
    digestBuf := NewBuffer(digestCount)
    defer digestBuf.Clear()


    C.vscf_sha384_finish(this.ctx, digestBuf)

    return digestBuf.GetData() /* r7 */
}
