package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


type BrainkeyClient struct {
    cCtx *C.vscf_brainkey_client_t /*ct2*/
}
const (
    BrainkeyClientPointLen uint32 = 65
    BrainkeyClientMpiLen uint32 = 32
    BrainkeyClientSeedLen uint32 = 32
    BrainkeyClientMaxPasswordLen uint32 = 128
    BrainkeyClientMaxKeyNameLen uint32 = 128
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
func newBrainkeyClientWithCtx(ctx *C.vscf_brainkey_client_t /*ct2*/) *BrainkeyClient {
    obj := &BrainkeyClient {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*BrainkeyClient).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newBrainkeyClientCopy(ctx *C.vscf_brainkey_client_t /*ct2*/) *BrainkeyClient {
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

/*
* Random used for key generation, proofs, etc.
*/
func (obj *BrainkeyClient) SetRandom(random Random) {
    C.vscf_brainkey_client_release_random(obj.cCtx)
    C.vscf_brainkey_client_use_random(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(random.Ctx())))

    runtime.KeepAlive(random)
    runtime.KeepAlive(obj)
}

/*
* Random used for crypto operations to make them const-time
*/
func (obj *BrainkeyClient) SetOperationRandom(operationRandom Random) {
    C.vscf_brainkey_client_release_operation_random(obj.cCtx)
    C.vscf_brainkey_client_use_operation_random(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(operationRandom.Ctx())))

    runtime.KeepAlive(operationRandom)
    runtime.KeepAlive(obj)
}

func (obj *BrainkeyClient) SetupDefaults() error {
    proxyResult := /*pr4*/C.vscf_brainkey_client_setup_defaults(obj.cCtx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    runtime.KeepAlive(obj)

    return nil
}

func (obj *BrainkeyClient) Blind(password []byte) ([]byte, []byte, error) {
    deblindFactorBuf, deblindFactorBufErr := bufferNewBuffer(int(BrainkeyClientMpiLen /* lg4 */))
    if deblindFactorBufErr != nil {
        return nil, nil, deblindFactorBufErr
    }
    defer deblindFactorBuf.Delete()

    blindedPointBuf, blindedPointBufErr := bufferNewBuffer(int(BrainkeyClientPointLen /* lg4 */))
    if blindedPointBufErr != nil {
        return nil, nil, blindedPointBufErr
    }
    defer blindedPointBuf.Delete()
    passwordData := helperWrapData (password)

    proxyResult := /*pr4*/C.vscf_brainkey_client_blind(obj.cCtx, passwordData, deblindFactorBuf.ctx, blindedPointBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, nil, err
    }

    runtime.KeepAlive(obj)

    return deblindFactorBuf.getData() /* r7 */, blindedPointBuf.getData() /* r7 */, nil
}

func (obj *BrainkeyClient) Deblind(password []byte, hardenedPoint []byte, deblindFactor []byte, keyName []byte) ([]byte, error) {
    seedBuf, seedBufErr := bufferNewBuffer(int(BrainkeyClientPointLen /* lg4 */))
    if seedBufErr != nil {
        return nil, seedBufErr
    }
    defer seedBuf.Delete()
    passwordData := helperWrapData (password)
    hardenedPointData := helperWrapData (hardenedPoint)
    deblindFactorData := helperWrapData (deblindFactor)
    keyNameData := helperWrapData (keyName)

    proxyResult := /*pr4*/C.vscf_brainkey_client_deblind(obj.cCtx, passwordData, hardenedPointData, deblindFactorData, keyNameData, seedBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return seedBuf.getData() /* r7 */, nil
}
