package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


type BrainkeyClient struct {
    cCtx *C.vscf_brainkey_client_t
}
const (
    BrainkeyClientPointLen uint = 65
    BrainkeyClientMpiLen uint = 32
    BrainkeyClientSeedLen uint = 32
    BrainkeyClientMaxPasswordLen uint = 128
    BrainkeyClientMaxKeyNameLen uint = 128
)

/* Handle underlying C context. */
func (obj *BrainkeyClient) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewBrainkeyClient() *BrainkeyClient {
    ctx := C.vscf_brainkey_client_new()
    obj := &BrainkeyClient {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*BrainkeyClient).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newBrainkeyClientWithCtx(ctx *C.vscf_brainkey_client_t) *BrainkeyClient {
    obj := &BrainkeyClient {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*BrainkeyClient).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newBrainkeyClientCopy(ctx *C.vscf_brainkey_client_t) *BrainkeyClient {
    obj := &BrainkeyClient {
        cCtx: C.vscf_brainkey_client_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*BrainkeyClient).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *BrainkeyClient) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *BrainkeyClient) delete() {
    C.vscf_brainkey_client_delete(obj.cCtx)
}

func (obj *BrainkeyClient) SetRandom(random Random) {
    C.vscf_brainkey_client_release_random(obj.cCtx)
    C.vscf_brainkey_client_use_random(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(random.Ctx())))

    runtime.KeepAlive(random)
    runtime.KeepAlive(obj)
}

func (obj *BrainkeyClient) SetOperationRandom(operationRandom Random) {
    C.vscf_brainkey_client_release_operation_random(obj.cCtx)
    C.vscf_brainkey_client_use_operation_random(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(operationRandom.Ctx())))

    runtime.KeepAlive(operationRandom)
    runtime.KeepAlive(obj)
}

func (obj *BrainkeyClient) SetupDefaults() error {
    proxyResult := C.vscf_brainkey_client_setup_defaults(obj.cCtx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    runtime.KeepAlive(obj)

    return nil
}

func (obj *BrainkeyClient) Blind(password []byte) ([]byte, []byte, error) {
    deblindFactorBuf, deblindFactorBufErr := newBuffer(int(BrainkeyClientMpiLen))
    if deblindFactorBufErr != nil {
        return nil, nil, deblindFactorBufErr
    }
    defer deblindFactorBuf.delete()

    blindedPointBuf, blindedPointBufErr := newBuffer(int(BrainkeyClientPointLen))
    if blindedPointBufErr != nil {
        return nil, nil, blindedPointBufErr
    }
    defer blindedPointBuf.delete()
    passwordData := helperWrapData (password)

    proxyResult := C.vscf_brainkey_client_blind(obj.cCtx, passwordData, deblindFactorBuf.ctx, blindedPointBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, nil, err
    }

    runtime.KeepAlive(obj)

    return deblindFactorBuf.getData(), blindedPointBuf.getData(), nil
}

func (obj *BrainkeyClient) Deblind(password []byte, hardenedPoint []byte, deblindFactor []byte, keyName []byte) ([]byte, error) {
    seedBuf, seedBufErr := newBuffer(int(BrainkeyClientPointLen))
    if seedBufErr != nil {
        return nil, seedBufErr
    }
    defer seedBuf.delete()
    passwordData := helperWrapData (password)
    hardenedPointData := helperWrapData (hardenedPoint)
    deblindFactorData := helperWrapData (deblindFactor)
    keyNameData := helperWrapData (keyName)

    proxyResult := C.vscf_brainkey_client_deblind(obj.cCtx, passwordData, hardenedPointData, deblindFactorData, keyNameData, seedBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return seedBuf.getData(), nil
}

/*
* Verifies the DLEQ proof that hardened_point = x * blinded_point where x corresponds
* to server_public_key = x * G. Must be called before deblind() to authenticate
* the server response.
*/
func (obj *BrainkeyClient) Verify(blindedPoint []byte, hardenedPoint []byte, serverPublicKey []byte, proofValueC []byte, proofValueS []byte) (bool, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    blindedPointData := helperWrapData (blindedPoint)
    hardenedPointData := helperWrapData (hardenedPoint)
    serverPublicKeyData := helperWrapData (serverPublicKey)
    proofValueCData := helperWrapData (proofValueC)
    proofValueSData := helperWrapData (proofValueS)

    proxyResult := C.vscf_brainkey_client_verify(obj.cCtx, blindedPointData, hardenedPointData, serverPublicKeyData, proofValueCData, proofValueSData, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return false, err
    }

    runtime.KeepAlive(obj)

    return proxyResult, nil
}
