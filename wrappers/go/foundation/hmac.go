package foundation

// #cgo CFLAGS: -I${SRCDIR}/../../../build/library/foundation/include/virgil/crypto/foundation
// #cgo CFLAGS: -I${SRCDIR}/../../../library/foundation/include/virgil/crypto/foundation
// #cgo LDFLAGS: -L${SRCDIR}/../../java/binaries/linux/lib -lvscf_foundation_java
// #include <vscf_foundation_public.h>
import "C"
import . "virgil/common"

/*
* Virgil Security implementation of HMAC algorithm (RFC 2104) (FIPS PUB 198-1).
*/
type Hmac struct {
    IAlg
    IMac
    ctx *C.vscf_impl_t
}

func (this Hmac) SetHash (hash IHash) {
    C.vscf_hmac_release_hash(this.ctx)
    C.vscf_hmac_use_hash(this.ctx, hash.Ctx())
}

/* Handle underlying C context. */
func (this Hmac) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewHmac () *Hmac {
    ctx := C.vscf_hmac_new()
    return &Hmac {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewHmacWithCtx (ctx *C.vscf_impl_t) *Hmac {
    return &Hmac {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewHmacCopy (ctx *C.vscf_impl_t) *Hmac {
    return &Hmac {
        ctx: C.vscf_hmac_shallow_copy(ctx),
    }
}

/*
* Provide algorithm identificator.
*/
func (this Hmac) AlgId () AlgId {
    proxyResult := C.vscf_hmac_alg_id(this.ctx)

    return AlgId(proxyResult) /* r8 */
}

/*
* Produce object with algorithm information and configuration parameters.
*/
func (this Hmac) ProduceAlgInfo () IAlgInfo {
    proxyResult := C.vscf_hmac_produce_alg_info(this.ctx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Restore algorithm configuration from the given object.
*/
func (this Hmac) RestoreAlgInfo (algInfo IAlgInfo) {
    proxyResult := C.vscf_hmac_restore_alg_info(this.ctx, algInfo.Ctx())

    FoundationErrorHandleStatus(proxyResult)
}

/*
* Size of the digest (mac output) in bytes.
*/
func (this Hmac) DigestLen () int32 {
    proxyResult := C.vscf_hmac_digest_len(this.ctx)

    return proxyResult //r9
}

/*
* Calculate MAC over given data.
*/
func (this Hmac) Mac (key []byte, data []byte) []byte {
    macCount := this.DigestLen() /* lg2 */
    macBuf := NewBuffer(macCount)
    defer macBuf.Clear()


    C.vscf_hmac_mac(this.ctx, WrapData(key), WrapData(data), macBuf)

    return macBuf.GetData() /* r7 */
}

/*
* Start a new MAC.
*/
func (this Hmac) Start (key []byte) {
    C.vscf_hmac_start(this.ctx, WrapData(key))
}

/*
* Add given data to the MAC.
*/
func (this Hmac) Update (data []byte) {
    C.vscf_hmac_update(this.ctx, WrapData(data))
}

/*
* Accomplish MAC and return it's result (a message digest).
*/
func (this Hmac) Finish () []byte {
    macCount := this.DigestLen() /* lg2 */
    macBuf := NewBuffer(macCount)
    defer macBuf.Clear()


    C.vscf_hmac_finish(this.ctx, macBuf)

    return macBuf.GetData() /* r7 */
}

/*
* Prepare to authenticate a new message with the same key
* as the previous MAC operation.
*/
func (this Hmac) Reset () {
    C.vscf_hmac_reset(this.ctx)
}
