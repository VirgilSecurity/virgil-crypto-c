package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"

/*
* Sign data of any size.
*/
type Signer struct {
    cCtx *C.vscf_signer_t /*ct2*/
}

/* Handle underlying C context. */
func (this Signer) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(this.cCtx)
}

func NewSigner () *Signer {
    ctx := C.vscf_signer_new()
    return &Signer {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newSignerWithCtx (ctx *C.vscf_signer_t /*ct2*/) *Signer {
    return &Signer {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newSignerCopy (ctx *C.vscf_signer_t /*ct2*/) *Signer {
    return &Signer {
        cCtx: C.vscf_signer_shallow_copy(ctx),
    }
}

/// Release underlying C context.
func (this Signer) close () {
    C.vscf_signer_delete(this.cCtx)
}

func (this Signer) SetHash (hash IHash) {
    C.vscf_signer_release_hash(this.cCtx)
    C.vscf_signer_use_hash(this.cCtx, (*C.vscf_impl_t)(hash.ctx()))
}

func (this Signer) SetRandom (random IRandom) {
    C.vscf_signer_release_random(this.cCtx)
    C.vscf_signer_use_random(this.cCtx, (*C.vscf_impl_t)(random.ctx()))
}

/*
* Start a processing a new signature.
*/
func (this Signer) Reset () {
    C.vscf_signer_reset(this.cCtx)

    return
}

/*
* Add given data to the signed data.
*/
func (this Signer) AppendData (data []byte) {
    dataData := C.vsc_data((*C.uint8_t)(&data[0]), C.size_t(len(data)))

    C.vscf_signer_append_data(this.cCtx, dataData)

    return
}

/*
* Return length of the signature.
*/
func (this Signer) SignatureLen (privateKey IPrivateKey) uint32 {
    proxyResult := /*pr4*/C.vscf_signer_signature_len(this.cCtx, (*C.vscf_impl_t)(privateKey.ctx()))

    return uint32(proxyResult) /* r9 */
}

/*
* Accomplish signing and return signature.
*/
func (this Signer) Sign (privateKey IPrivateKey) ([]byte, error) {
    signatureCount := C.ulong(this.SignatureLen(privateKey.(IPrivateKey)) /* lg2 */)
    signatureMemory := make([]byte, int(C.vsc_buffer_ctx_size() + signatureCount))
    signatureBuf := (*C.vsc_buffer_t)(unsafe.Pointer(&signatureMemory[0]))
    signatureData := signatureMemory[int(C.vsc_buffer_ctx_size()):]
    C.vsc_buffer_init(signatureBuf)
    C.vsc_buffer_use(signatureBuf, (*C.byte)(unsafe.Pointer(&signatureData[0])), signatureCount)
    defer C.vsc_buffer_delete(signatureBuf)


    proxyResult := /*pr4*/C.vscf_signer_sign(this.cCtx, (*C.vscf_impl_t)(privateKey.ctx()), signatureBuf)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return signatureData[0:C.vsc_buffer_len(signatureBuf)] /* r7 */, nil
}
