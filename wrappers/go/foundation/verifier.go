package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"


/*
* Verify data of any size.
* Compatible with the class "signer".
*/
type Verifier struct {
    cCtx *C.vscf_verifier_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *Verifier) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(obj.cCtx)
}

func NewVerifier () *Verifier {
    ctx := C.vscf_verifier_new()
    return &Verifier {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newVerifierWithCtx (ctx *C.vscf_verifier_t /*ct2*/) *Verifier {
    return &Verifier {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newVerifierCopy (ctx *C.vscf_verifier_t /*ct2*/) *Verifier {
    return &Verifier {
        cCtx: C.vscf_verifier_shallow_copy(ctx),
    }
}

/// Release underlying C context.
func (obj *Verifier) clear () {
    C.vscf_verifier_delete(obj.cCtx)
}

/*
* Start verifying a signature.
*/
func (obj *Verifier) Reset (signature []byte) error {
    signatureData := helperWrapData (signature)

    proxyResult := /*pr4*/C.vscf_verifier_reset(obj.cCtx, signatureData)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}

/*
* Add given data to the signed data.
*/
func (obj *Verifier) AppendData (data []byte) {
    dataData := helperWrapData (data)

    C.vscf_verifier_append_data(obj.cCtx, dataData)

    return
}

/*
* Verify accumulated data.
*/
func (obj *Verifier) Verify (publicKey IPublicKey) bool {
    proxyResult := /*pr4*/C.vscf_verifier_verify(obj.cCtx, (*C.vscf_impl_t)(publicKey.ctx()))

    return bool(proxyResult) /* r9 */
}
