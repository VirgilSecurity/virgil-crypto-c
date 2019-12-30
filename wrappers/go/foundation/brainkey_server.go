package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


type BrainkeyServer struct {
    cCtx *C.vscf_brainkey_server_t /*ct2*/
}
const (
    BrainkeyServerPointLen uint = 65
    BrainkeyServerMpiLen uint = 32
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
func newBrainkeyServerWithCtx(ctx *C.vscf_brainkey_server_t /*ct2*/) *BrainkeyServer {
    obj := &BrainkeyServer {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*BrainkeyServer).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newBrainkeyServerCopy(ctx *C.vscf_brainkey_server_t /*ct2*/) *BrainkeyServer {
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

/*
* Random used for key generation, proofs, etc.
*/
func (obj *BrainkeyServer) SetRandom(random Random) {
    C.vscf_brainkey_server_release_random(obj.cCtx)
    C.vscf_brainkey_server_use_random(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(random.Ctx())))

    runtime.KeepAlive(random)
    runtime.KeepAlive(obj)
}

/*
* Random used for crypto operations to make them const-time
*/
func (obj *BrainkeyServer) SetOperationRandom(operationRandom Random) {
    C.vscf_brainkey_server_release_operation_random(obj.cCtx)
    C.vscf_brainkey_server_use_operation_random(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(operationRandom.Ctx())))

    runtime.KeepAlive(operationRandom)
    runtime.KeepAlive(obj)
}

func (obj *BrainkeyServer) SetupDefaults() error {
    proxyResult := /*pr4*/C.vscf_brainkey_server_setup_defaults(obj.cCtx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    runtime.KeepAlive(obj)

    return nil
}

func (obj *BrainkeyServer) GenerateIdentitySecret() ([]byte, error) {
    identitySecretBuf, identitySecretBufErr := bufferNewBuffer(int(BrainkeyServerMpiLen /* lg4 */))
    if identitySecretBufErr != nil {
        return nil, identitySecretBufErr
    }
    defer identitySecretBuf.Delete()


    proxyResult := /*pr4*/C.vscf_brainkey_server_generate_identity_secret(obj.cCtx, identitySecretBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return identitySecretBuf.getData() /* r7 */, nil
}

func (obj *BrainkeyServer) Harden(identitySecret []byte, blindedPoint []byte) ([]byte, error) {
    hardenedPointBuf, hardenedPointBufErr := bufferNewBuffer(int(BrainkeyServerPointLen /* lg4 */))
    if hardenedPointBufErr != nil {
        return nil, hardenedPointBufErr
    }
    defer hardenedPointBuf.Delete()
    identitySecretData := helperWrapData (identitySecret)
    blindedPointData := helperWrapData (blindedPoint)

    proxyResult := /*pr4*/C.vscf_brainkey_server_harden(obj.cCtx, identitySecretData, blindedPointData, hardenedPointBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return hardenedPointBuf.getData() /* r7 */, nil
}
