package phe

// #include <virgil/crypto/phe/vsce_phe_public.h>
import "C"
import unsafe "unsafe"
import "runtime"
import foundation "virgil/foundation"


/*
* Class for server-side PHE crypto operations.
* This class is thread-safe in case if VSCE_MULTI_THREADING defined.
*/
type PheServer struct {
    cCtx *C.vsce_phe_server_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *PheServer) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewPheServer() *PheServer {
    ctx := C.vsce_phe_server_new()
    obj := &PheServer {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*PheServer).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newPheServerWithCtx(ctx *C.vsce_phe_server_t /*ct2*/) *PheServer {
    obj := &PheServer {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*PheServer).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newPheServerCopy(ctx *C.vsce_phe_server_t /*ct2*/) *PheServer {
    obj := &PheServer {
        cCtx: C.vsce_phe_server_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*PheServer).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *PheServer) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *PheServer) delete() {
    C.vsce_phe_server_delete(obj.cCtx)
}

/*
* Random used for key generation, proofs, etc.
*/
func (obj *PheServer) SetRandom(random foundation.Random) {
    C.vsce_phe_server_release_random(obj.cCtx)
    C.vsce_phe_server_use_random(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(random.Ctx())))

    runtime.KeepAlive(random)
    runtime.KeepAlive(obj)
}

/*
* Random used for crypto operations to make them const-time
*/
func (obj *PheServer) SetOperationRandom(operationRandom foundation.Random) {
    C.vsce_phe_server_release_operation_random(obj.cCtx)
    C.vsce_phe_server_use_operation_random(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(operationRandom.Ctx())))

    runtime.KeepAlive(operationRandom)
    runtime.KeepAlive(obj)
}

/*
* Setups dependencies with default values.
*/
func (obj *PheServer) SetupDefaults() error {
    proxyResult := /*pr4*/C.vsce_phe_server_setup_defaults(obj.cCtx)

    err := PheErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    runtime.KeepAlive(obj)

    return nil
}

/*
* Generates new NIST P-256 server key pair for some client
*/
func (obj *PheServer) GenerateServerKeyPair() ([]byte, []byte, error) {
    serverPrivateKeyBuf, serverPrivateKeyBufErr := bufferNewBuffer(int(PheCommonPhePrivateKeyLength /* lg4 */))
    if serverPrivateKeyBufErr != nil {
        return nil, nil, serverPrivateKeyBufErr
    }
    defer serverPrivateKeyBuf.Delete()

    serverPublicKeyBuf, serverPublicKeyBufErr := bufferNewBuffer(int(PheCommonPhePublicKeyLength /* lg4 */))
    if serverPublicKeyBufErr != nil {
        return nil, nil, serverPublicKeyBufErr
    }
    defer serverPublicKeyBuf.Delete()


    proxyResult := /*pr4*/C.vsce_phe_server_generate_server_key_pair(obj.cCtx, serverPrivateKeyBuf.ctx, serverPublicKeyBuf.ctx)

    err := PheErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, nil, err
    }

    runtime.KeepAlive(obj)

    return serverPrivateKeyBuf.getData() /* r7 */, serverPublicKeyBuf.getData() /* r7 */, nil
}

/*
* Buffer size needed to fit EnrollmentResponse
*/
func (obj *PheServer) EnrollmentResponseLen() uint32 {
    proxyResult := /*pr4*/C.vsce_phe_server_enrollment_response_len(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint32(proxyResult) /* r9 */
}

/*
* Generates a new random enrollment and proof for a new user
*/
func (obj *PheServer) GetEnrollment(serverPrivateKey []byte, serverPublicKey []byte) ([]byte, error) {
    enrollmentResponseBuf, enrollmentResponseBufErr := bufferNewBuffer(int(obj.EnrollmentResponseLen() /* lg2 */))
    if enrollmentResponseBufErr != nil {
        return nil, enrollmentResponseBufErr
    }
    defer enrollmentResponseBuf.Delete()
    serverPrivateKeyData := helperWrapData (serverPrivateKey)
    serverPublicKeyData := helperWrapData (serverPublicKey)

    proxyResult := /*pr4*/C.vsce_phe_server_get_enrollment(obj.cCtx, serverPrivateKeyData, serverPublicKeyData, enrollmentResponseBuf.ctx)

    err := PheErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return enrollmentResponseBuf.getData() /* r7 */, nil
}

/*
* Buffer size needed to fit VerifyPasswordResponse
*/
func (obj *PheServer) VerifyPasswordResponseLen() uint32 {
    proxyResult := /*pr4*/C.vsce_phe_server_verify_password_response_len(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint32(proxyResult) /* r9 */
}

/*
* Verifies existing user's password and generates response with proof
*/
func (obj *PheServer) VerifyPassword(serverPrivateKey []byte, serverPublicKey []byte, verifyPasswordRequest []byte) ([]byte, error) {
    verifyPasswordResponseBuf, verifyPasswordResponseBufErr := bufferNewBuffer(int(obj.VerifyPasswordResponseLen() /* lg2 */))
    if verifyPasswordResponseBufErr != nil {
        return nil, verifyPasswordResponseBufErr
    }
    defer verifyPasswordResponseBuf.Delete()
    serverPrivateKeyData := helperWrapData (serverPrivateKey)
    serverPublicKeyData := helperWrapData (serverPublicKey)
    verifyPasswordRequestData := helperWrapData (verifyPasswordRequest)

    proxyResult := /*pr4*/C.vsce_phe_server_verify_password(obj.cCtx, serverPrivateKeyData, serverPublicKeyData, verifyPasswordRequestData, verifyPasswordResponseBuf.ctx)

    err := PheErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return verifyPasswordResponseBuf.getData() /* r7 */, nil
}

/*
* Buffer size needed to fit UpdateToken
*/
func (obj *PheServer) UpdateTokenLen() uint32 {
    proxyResult := /*pr4*/C.vsce_phe_server_update_token_len(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint32(proxyResult) /* r9 */
}

/*
* Updates server's private and public keys and issues an update token for use on client's side
*/
func (obj *PheServer) RotateKeys(serverPrivateKey []byte) ([]byte, []byte, []byte, error) {
    newServerPrivateKeyBuf, newServerPrivateKeyBufErr := bufferNewBuffer(int(PheCommonPhePrivateKeyLength /* lg4 */))
    if newServerPrivateKeyBufErr != nil {
        return nil, nil, nil, newServerPrivateKeyBufErr
    }
    defer newServerPrivateKeyBuf.Delete()

    newServerPublicKeyBuf, newServerPublicKeyBufErr := bufferNewBuffer(int(PheCommonPhePublicKeyLength /* lg4 */))
    if newServerPublicKeyBufErr != nil {
        return nil, nil, nil, newServerPublicKeyBufErr
    }
    defer newServerPublicKeyBuf.Delete()

    updateTokenBuf, updateTokenBufErr := bufferNewBuffer(int(obj.UpdateTokenLen() /* lg2 */))
    if updateTokenBufErr != nil {
        return nil, nil, nil, updateTokenBufErr
    }
    defer updateTokenBuf.Delete()
    serverPrivateKeyData := helperWrapData (serverPrivateKey)

    proxyResult := /*pr4*/C.vsce_phe_server_rotate_keys(obj.cCtx, serverPrivateKeyData, newServerPrivateKeyBuf.ctx, newServerPublicKeyBuf.ctx, updateTokenBuf.ctx)

    err := PheErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, nil, nil, err
    }

    runtime.KeepAlive(obj)

    return newServerPrivateKeyBuf.getData() /* r7 */, newServerPublicKeyBuf.getData() /* r7 */, updateTokenBuf.getData() /* r7 */, nil
}
