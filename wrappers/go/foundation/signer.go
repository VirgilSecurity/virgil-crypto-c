package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_common
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_foundation
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import . "virgil/common"

/*
* Sign data of any size.
*/
type Signer struct {
    ctx *C.vscf_impl_t
}

/* Handle underlying C context. */
func (this Signer) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewSigner () *Signer {
    ctx := C.vscf_signer_new()
    return &Signer {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewSignerWithCtx (ctx *C.vscf_impl_t) *Signer {
    return &Signer {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewSignerCopy (ctx *C.vscf_impl_t) *Signer {
    return &Signer {
        ctx: C.vscf_signer_shallow_copy(ctx),
    }
}

func (this Signer) SetHash (hash IHash) {
    C.vscf_signer_release_hash(this.ctx)
    C.vscf_signer_use_hash(this.ctx, hash.Ctx())
}

func (this Signer) SetRandom (random IRandom) {
    C.vscf_signer_release_random(this.ctx)
    C.vscf_signer_use_random(this.ctx, random.Ctx())
}

/*
* Start a processing a new signature.
*/
func (this Signer) Reset () {
    C.vscf_signer_reset(this.ctx)
}

/*
* Add given data to the signed data.
*/
func (this Signer) AppendData (data []byte) {
    C.vscf_signer_append_data(this.ctx, WrapData(data))
}

/*
* Return length of the signature.
*/
func (this Signer) SignatureLen (privateKey IPrivateKey) int32 {
    proxyResult := C.vscf_signer_signature_len(this.ctx, privateKey.Ctx())

    return proxyResult //r9
}

/*
* Accomplish signing and return signature.
*/
func (this Signer) Sign (privateKey IPrivateKey) []byte {
    signatureCount := this.SignatureLen(privateKey) /* lg2 */
    signatureBuf := NewBuffer(signatureCount)
    defer signatureBuf.Clear()


    proxyResult := C.vscf_signer_sign(this.ctx, privateKey.Ctx(), signatureBuf)

    FoundationErrorHandleStatus(proxyResult)

    return signatureBuf.GetData() /* r7 */
}
