package foundation

// #cgo CFLAGS: -I${SRCDIR}/../../../build/library/foundation/include/virgil/crypto/foundation
// #cgo CFLAGS: -I${SRCDIR}/../../../library/foundation/include/virgil/crypto/foundation
// #cgo LDFLAGS: -L${SRCDIR}/../../java/binaries/linux/lib -lvscf_foundation_java
// #include <vscf_foundation_public.h>
import "C"
import . "virgil/common"

/*
* This is MbedTLS implementation of SHA224.
*/
type Sha224 struct {
    IAlg
    IHash
    ctx *C.vscf_impl_t
}

/* Handle underlying C context. */
func (this Sha224) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewSha224 () *Sha224 {
    ctx := C.vscf_sha224_new()
    return &Sha224 {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewSha224WithCtx (ctx *C.vscf_impl_t) *Sha224 {
    return &Sha224 {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewSha224Copy (ctx *C.vscf_impl_t) *Sha224 {
    return &Sha224 {
        ctx: C.vscf_sha224_shallow_copy(ctx),
    }
}

/*
* Provide algorithm identificator.
*/
func (this Sha224) AlgId () AlgId {
    proxyResult := C.vscf_sha224_alg_id(this.ctx)

    return AlgId(proxyResult) /* r8 */
}

/*
* Produce object with algorithm information and configuration parameters.
*/
func (this Sha224) ProduceAlgInfo () IAlgInfo {
    proxyResult := C.vscf_sha224_produce_alg_info(this.ctx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Restore algorithm configuration from the given object.
*/
func (this Sha224) RestoreAlgInfo (algInfo IAlgInfo) {
    proxyResult := C.vscf_sha224_restore_alg_info(this.ctx, algInfo.Ctx())

    FoundationErrorHandleStatus(proxyResult)
}

/*
* Length of the digest (hashing output) in bytes.
*/
func (this Sha224) getDigestLen () int32 {
    return 28
}

/*
* Block length of the digest function in bytes.
*/
func (this Sha224) getBlockLen () int32 {
    return 64
}

/*
* Calculate hash over given data.
*/
func (this Sha224) Hash (data []byte) []byte {
    digestCount := this.getDigestLen() /* lg3 */
    digestBuf := NewBuffer(digestCount)
    defer digestBuf.Clear()


    C.vscf_sha224_hash(WrapData(data), digestBuf)

    return digestBuf.GetData() /* r7 */
}

/*
* Start a new hashing.
*/
func (this Sha224) Start () {
    C.vscf_sha224_start(this.ctx)
}

/*
* Add given data to the hash.
*/
func (this Sha224) Update (data []byte) {
    C.vscf_sha224_update(this.ctx, WrapData(data))
}

/*
* Accompilsh hashing and return it's result (a message digest).
*/
func (this Sha224) Finish () []byte {
    digestCount := this.getDigestLen() /* lg3 */
    digestBuf := NewBuffer(digestCount)
    defer digestBuf.Clear()


    C.vscf_sha224_finish(this.ctx, digestBuf)

    return digestBuf.GetData() /* r7 */
}
