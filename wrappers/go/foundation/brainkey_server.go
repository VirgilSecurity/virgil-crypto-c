package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"


type BrainkeyServer struct {
    cCtx *C.vscf_brainkey_server_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *BrainkeyServer) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(obj.cCtx)
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
func (obj *BrainkeyServer) clear () {
    C.vscf_brainkey_server_delete(obj.cCtx)
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
func (obj *BrainkeyServer) SetRandom (random IRandom) {
    C.vscf_brainkey_server_release_random(obj.cCtx)
    C.vscf_brainkey_server_use_random(obj.cCtx, (*C.vscf_impl_t)(random.ctx()))
}

/*
* Random used for crypto operations to make them const-time
*/
func (obj *BrainkeyServer) SetOperationRandom (operationRandom IRandom) {
    C.vscf_brainkey_server_release_operation_random(obj.cCtx)
    C.vscf_brainkey_server_use_operation_random(obj.cCtx, (*C.vscf_impl_t)(operationRandom.ctx()))
}

func (obj *BrainkeyServer) SetupDefaults () error {
    proxyResult := /*pr4*/C.vscf_brainkey_server_setup_defaults(obj.cCtx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}

func (obj *BrainkeyServer) GenerateIdentitySecret () ([]byte, error) {
    identitySecretBuf, identitySecretBufErr := bufferNewBuffer(int(BrainkeyServerGetMpiLen() /* lg4 */))
    if identitySecretBufErr != nil {
        return nil, identitySecretBufErr
    }
    defer identitySecretBuf.clear()


    proxyResult := /*pr4*/C.vscf_brainkey_server_generate_identity_secret(obj.cCtx, identitySecretBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return identitySecretBuf.getData() /* r7 */, nil
}

func (obj *BrainkeyServer) Harden (identitySecret []byte, blindedPoint []byte) ([]byte, error) {
    hardenedPointBuf, hardenedPointBufErr := bufferNewBuffer(int(BrainkeyServerGetPointLen() /* lg4 */))
    if hardenedPointBufErr != nil {
        return nil, hardenedPointBufErr
    }
    defer hardenedPointBuf.clear()
    identitySecretData := helperWrapData (identitySecret)
    blindedPointData := helperWrapData (blindedPoint)

    proxyResult := /*pr4*/C.vscf_brainkey_server_harden(obj.cCtx, identitySecretData, blindedPointData, hardenedPointBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return hardenedPointBuf.getData() /* r7 */, nil
}
