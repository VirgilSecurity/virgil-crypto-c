package foundation

// #cgo CFLAGS: -I${SRCDIR}/../../../build/library/foundation/include/virgil/crypto/foundation
// #cgo CFLAGS: -I${SRCDIR}/../../../library/foundation/include/virgil/crypto/foundation
// #cgo LDFLAGS: -L${SRCDIR}/../../java/binaries/linux/lib -lvscf_foundation_java
// #include <vscf_foundation_public.h>
import "C"
import . "virgil/common"

/*
* Verify data of any size.
* Compatible with the class "signer".
*/
type Verifier struct {
    ctx *C.vscf_impl_t
}

/* Handle underlying C context. */
func (this Verifier) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewVerifier () *Verifier {
    ctx := C.vscf_verifier_new()
    return &Verifier {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewVerifierWithCtx (ctx *C.vscf_impl_t) *Verifier {
    return &Verifier {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewVerifierCopy (ctx *C.vscf_impl_t) *Verifier {
    return &Verifier {
        ctx: C.vscf_verifier_shallow_copy(ctx),
    }
}

/*
* Start verifying a signature.
*/
func (this Verifier) Reset (signature []byte) {
    proxyResult := C.vscf_verifier_reset(this.ctx, WrapData(signature))

    FoundationErrorHandleStatus(proxyResult)
}

/*
* Add given data to the signed data.
*/
func (this Verifier) AppendData (data []byte) {
    C.vscf_verifier_append_data(this.ctx, WrapData(data))
}

/*
* Verify accumulated data.
*/
func (this Verifier) Verify (publicKey IPublicKey) bool {
    proxyResult := C.vscf_verifier_verify(this.ctx, publicKey.Ctx())

    return proxyResult //r9
}
