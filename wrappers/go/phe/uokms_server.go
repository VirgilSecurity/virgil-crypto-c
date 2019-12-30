package phe

// #include <virgil/crypto/phe/vsce_phe_public.h>
import "C"
import unsafe "unsafe"
import "runtime"
import foundation "virgil/foundation"


/*
* Class implements UOKMS for server-side.
*/
type UokmsServer struct {
    cCtx *C.vsce_uokms_server_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *UokmsServer) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewUokmsServer() *UokmsServer {
    ctx := C.vsce_uokms_server_new()
    obj := &UokmsServer {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*UokmsServer).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newUokmsServerWithCtx(ctx *C.vsce_uokms_server_t /*ct2*/) *UokmsServer {
    obj := &UokmsServer {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*UokmsServer).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newUokmsServerCopy(ctx *C.vsce_uokms_server_t /*ct2*/) *UokmsServer {
    obj := &UokmsServer {
        cCtx: C.vsce_uokms_server_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*UokmsServer).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *UokmsServer) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *UokmsServer) delete() {
    C.vsce_uokms_server_delete(obj.cCtx)
}

/*
* Random used for key generation, proofs, etc.
*/
func (obj *UokmsServer) SetRandom(random foundation.Random) {
    C.vsce_uokms_server_release_random(obj.cCtx)
    C.vsce_uokms_server_use_random(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(random.Ctx())))

    runtime.KeepAlive(random)
    runtime.KeepAlive(obj)
}

/*
* Random used for crypto operations to make them const-time
*/
func (obj *UokmsServer) SetOperationRandom(operationRandom foundation.Random) {
    C.vsce_uokms_server_release_operation_random(obj.cCtx)
    C.vsce_uokms_server_use_operation_random(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(operationRandom.Ctx())))

    runtime.KeepAlive(operationRandom)
    runtime.KeepAlive(obj)
}

/*
* Setups dependencies with default values.
*/
func (obj *UokmsServer) SetupDefaults() error {
    proxyResult := /*pr4*/C.vsce_uokms_server_setup_defaults(obj.cCtx)

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
func (obj *UokmsServer) GenerateServerKeyPair() ([]byte, []byte, error) {
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


    proxyResult := /*pr4*/C.vsce_uokms_server_generate_server_key_pair(obj.cCtx, serverPrivateKeyBuf.ctx, serverPublicKeyBuf.ctx)

    err := PheErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, nil, err
    }

    runtime.KeepAlive(obj)

    return serverPrivateKeyBuf.getData() /* r7 */, serverPublicKeyBuf.getData() /* r7 */, nil
}

/*
* Buffer size needed to fit DecryptResponse
*/
func (obj *UokmsServer) DecryptResponseLen() uint {
    proxyResult := /*pr4*/C.vsce_uokms_server_decrypt_response_len(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Processed client's decrypt request
*/
func (obj *UokmsServer) ProcessDecryptRequest(serverPrivateKey []byte, decryptRequest []byte) ([]byte, error) {
    decryptResponseBuf, decryptResponseBufErr := bufferNewBuffer(int(obj.DecryptResponseLen() /* lg2 */))
    if decryptResponseBufErr != nil {
        return nil, decryptResponseBufErr
    }
    defer decryptResponseBuf.Delete()
    serverPrivateKeyData := helperWrapData (serverPrivateKey)
    decryptRequestData := helperWrapData (decryptRequest)

    proxyResult := /*pr4*/C.vsce_uokms_server_process_decrypt_request(obj.cCtx, serverPrivateKeyData, decryptRequestData, decryptResponseBuf.ctx)

    err := PheErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return decryptResponseBuf.getData() /* r7 */, nil
}

/*
* Updates server's private and public keys and issues an update token for use on client's side
*/
func (obj *UokmsServer) RotateKeys(serverPrivateKey []byte) ([]byte, []byte, []byte, error) {
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

    updateTokenBuf, updateTokenBufErr := bufferNewBuffer(int(PheCommonPhePublicKeyLength /* lg4 */))
    if updateTokenBufErr != nil {
        return nil, nil, nil, updateTokenBufErr
    }
    defer updateTokenBuf.Delete()
    serverPrivateKeyData := helperWrapData (serverPrivateKey)

    proxyResult := /*pr4*/C.vsce_uokms_server_rotate_keys(obj.cCtx, serverPrivateKeyData, newServerPrivateKeyBuf.ctx, newServerPublicKeyBuf.ctx, updateTokenBuf.ctx)

    err := PheErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, nil, nil, err
    }

    runtime.KeepAlive(obj)

    return newServerPrivateKeyBuf.getData() /* r7 */, newServerPublicKeyBuf.getData() /* r7 */, updateTokenBuf.getData() /* r7 */, nil
}
