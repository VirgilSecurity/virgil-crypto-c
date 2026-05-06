package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


type BrainkeyServer struct {
    cCtx *C.vscf_brainkey_server_t
}
const (
    BrainkeyServerPointLen uint = 65
    BrainkeyServerMpiLen uint = 32
    BrainkeyServerProofValueLen uint = 32
)

/* Handle underlying C context. */
func (obj *BrainkeyServer) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewBrainkeyServer() *BrainkeyServer {
    ctx := C.vscf_brainkey_server_new()
    obj := &BrainkeyServer {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*BrainkeyServer).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newBrainkeyServerWithCtx(ctx *C.vscf_brainkey_server_t) *BrainkeyServer {
    obj := &BrainkeyServer {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*BrainkeyServer).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newBrainkeyServerCopy(ctx *C.vscf_brainkey_server_t) *BrainkeyServer {
    obj := &BrainkeyServer {
        cCtx: C.vscf_brainkey_server_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*BrainkeyServer).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *BrainkeyServer) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *BrainkeyServer) delete() {
    C.vscf_brainkey_server_delete(obj.cCtx)
}

func (obj *BrainkeyServer) SetRandom(random Random) {
    C.vscf_brainkey_server_release_random(obj.cCtx)
    C.vscf_brainkey_server_use_random(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(random.Ctx())))

    runtime.KeepAlive(random)
    runtime.KeepAlive(obj)
}

func (obj *BrainkeyServer) SetOperationRandom(operationRandom Random) {
    C.vscf_brainkey_server_release_operation_random(obj.cCtx)
    C.vscf_brainkey_server_use_operation_random(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(operationRandom.Ctx())))

    runtime.KeepAlive(operationRandom)
    runtime.KeepAlive(obj)
}

func (obj *BrainkeyServer) SetupDefaults() error {
    proxyResult := C.vscf_brainkey_server_setup_defaults(obj.cCtx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    runtime.KeepAlive(obj)

    return nil
}

func (obj *BrainkeyServer) GenerateIdentitySecret() ([]byte, error) {
    identitySecretBuf, identitySecretBufErr := newBuffer(int(BrainkeyServerMpiLen))
    if identitySecretBufErr != nil {
        return nil, identitySecretBufErr
    }
    defer identitySecretBuf.delete()


    proxyResult := C.vscf_brainkey_server_generate_identity_secret(obj.cCtx, identitySecretBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return identitySecretBuf.getData(), nil
}

func (obj *BrainkeyServer) Harden(identitySecret []byte, blindedPoint []byte) ([]byte, error) {
    hardenedPointBuf, hardenedPointBufErr := newBuffer(int(BrainkeyServerPointLen))
    if hardenedPointBufErr != nil {
        return nil, hardenedPointBufErr
    }
    defer hardenedPointBuf.delete()
    identitySecretData := helperWrapData (identitySecret)
    blindedPointData := helperWrapData (blindedPoint)

    proxyResult := C.vscf_brainkey_server_harden(obj.cCtx, identitySecretData, blindedPointData, hardenedPointBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return hardenedPointBuf.getData(), nil
}

/*
* Computes the server's public key G_x = x*G from the given identity secret x.
* Required by the client to verify DLEQ proofs.
*/
func (obj *BrainkeyServer) ComputePublicKey(identitySecret []byte) ([]byte, error) {
    publicKeyBuf, publicKeyBufErr := newBuffer(int(BrainkeyServerPointLen))
    if publicKeyBufErr != nil {
        return nil, publicKeyBufErr
    }
    defer publicKeyBuf.delete()
    identitySecretData := helperWrapData (identitySecret)

    proxyResult := C.vscf_brainkey_server_compute_public_key(obj.cCtx, identitySecretData, publicKeyBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return publicKeyBuf.getData(), nil
}

/*
* Generates a DLEQ proof that hardened_point = x * blinded_point using the same
* identity secret x as server_public_key = x * G.
* Client must call verify() before deblind() to authenticate the server response.
*/
func (obj *BrainkeyServer) Prove(blindedPoint []byte, hardenedPoint []byte, identitySecret []byte, serverPublicKey []byte) (bool, []byte, []byte, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proofValueCBuf, proofValueCBufErr := newBuffer(int(BrainkeyServerProofValueLen))
    if proofValueCBufErr != nil {
        return false, nil, nil, proofValueCBufErr
    }
    defer proofValueCBuf.delete()

    proofValueSBuf, proofValueSBufErr := newBuffer(int(BrainkeyServerProofValueLen))
    if proofValueSBufErr != nil {
        return false, nil, nil, proofValueSBufErr
    }
    defer proofValueSBuf.delete()
    blindedPointData := helperWrapData (blindedPoint)
    hardenedPointData := helperWrapData (hardenedPoint)
    identitySecretData := helperWrapData (identitySecret)
    serverPublicKeyData := helperWrapData (serverPublicKey)

    proxyResult := C.vscf_brainkey_server_prove(obj.cCtx, blindedPointData, hardenedPointData, identitySecretData, serverPublicKeyData, proofValueCBuf.ctx, proofValueSBuf.ctx, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return false, nil, nil, err
    }

    runtime.KeepAlive(obj)

    return bool(proxyResult), proofValueCBuf.getData(), proofValueSBuf.getData(), nil
}
