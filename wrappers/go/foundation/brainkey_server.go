package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"

type BrainkeyServer struct {
    cCtx *C.vscf_brainkey_server_t /*ct2*/
}

/* Handle underlying C context. */
func (this BrainkeyServer) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(this.cCtx)
}

func NewBrainkeyServer () *BrainkeyServer {
    ctx := C.vscf_brainkey_server_new()
    return &BrainkeyServer {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newBrainkeyServerWithCtx (ctx *C.vscf_brainkey_server_t /*ct2*/) *BrainkeyServer {
    return &BrainkeyServer {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newBrainkeyServerCopy (ctx *C.vscf_brainkey_server_t /*ct2*/) *BrainkeyServer {
    return &BrainkeyServer {
        cCtx: C.vscf_brainkey_server_shallow_copy(ctx),
    }
}

/// Release underlying C context.
func (this BrainkeyServer) close () {
    C.vscf_brainkey_server_delete(this.cCtx)
}

func BrainkeyServerGetPointLen () uint32 {
    return 65
}

func BrainkeyServerGetMpiLen () uint32 {
    return 32
}

/*
* Random used for key generation, proofs, etc.
*/
func (this BrainkeyServer) SetRandom (random IRandom) {
    C.vscf_brainkey_server_release_random(this.cCtx)
    C.vscf_brainkey_server_use_random(this.cCtx, (*C.vscf_impl_t)(random.ctx()))
}

/*
* Random used for crypto operations to make them const-time
*/
func (this BrainkeyServer) SetOperationRandom (operationRandom IRandom) {
    C.vscf_brainkey_server_release_operation_random(this.cCtx)
    C.vscf_brainkey_server_use_operation_random(this.cCtx, (*C.vscf_impl_t)(operationRandom.ctx()))
}

func (this BrainkeyServer) SetupDefaults () error {
    proxyResult := /*pr4*/C.vscf_brainkey_server_setup_defaults(this.cCtx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}

func (this BrainkeyServer) GenerateIdentitySecret () ([]byte, error) {
    identitySecretCount := C.ulong(BrainkeyServerGetMpiLen() /* lg4 */)
    identitySecretMemory := make([]byte, int(C.vsc_buffer_ctx_size() + identitySecretCount))
    identitySecretBuf := (*C.vsc_buffer_t)(unsafe.Pointer(&identitySecretMemory[0]))
    identitySecretData := identitySecretMemory[int(C.vsc_buffer_ctx_size()):]
    C.vsc_buffer_init(identitySecretBuf)
    C.vsc_buffer_use(identitySecretBuf, (*C.byte)(unsafe.Pointer(&identitySecretData[0])), identitySecretCount)
    defer C.vsc_buffer_delete(identitySecretBuf)


    proxyResult := /*pr4*/C.vscf_brainkey_server_generate_identity_secret(this.cCtx, identitySecretBuf)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return identitySecretData[0:C.vsc_buffer_len(identitySecretBuf)] /* r7 */, nil
}

func (this BrainkeyServer) Harden (identitySecret []byte, blindedPoint []byte) ([]byte, error) {
    hardenedPointCount := C.ulong(BrainkeyServerGetPointLen() /* lg4 */)
    hardenedPointMemory := make([]byte, int(C.vsc_buffer_ctx_size() + hardenedPointCount))
    hardenedPointBuf := (*C.vsc_buffer_t)(unsafe.Pointer(&hardenedPointMemory[0]))
    hardenedPointData := hardenedPointMemory[int(C.vsc_buffer_ctx_size()):]
    C.vsc_buffer_init(hardenedPointBuf)
    C.vsc_buffer_use(hardenedPointBuf, (*C.byte)(unsafe.Pointer(&hardenedPointData[0])), hardenedPointCount)
    defer C.vsc_buffer_delete(hardenedPointBuf)
    identitySecretData := C.vsc_data((*C.uint8_t)(&identitySecret[0]), C.size_t(len(identitySecret)))
    blindedPointData := C.vsc_data((*C.uint8_t)(&blindedPoint[0]), C.size_t(len(blindedPoint)))

    proxyResult := /*pr4*/C.vscf_brainkey_server_harden(this.cCtx, identitySecretData, blindedPointData, hardenedPointBuf)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return hardenedPointData[0:C.vsc_buffer_len(hardenedPointBuf)] /* r7 */, nil
}
