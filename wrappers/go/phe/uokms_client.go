package phe

// #include <virgil/crypto/phe/vsce_phe_public.h>
import "C"
import unsafe "unsafe"
import "runtime"
import foundation "virgil/foundation"


/*
* Class implements UOKMS for client-side.
*/
type UokmsClient struct {
    cCtx *C.vsce_uokms_client_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *UokmsClient) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewUokmsClient() *UokmsClient {
    ctx := C.vsce_uokms_client_new()
    obj := &UokmsClient {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*UokmsClient).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newUokmsClientWithCtx(ctx *C.vsce_uokms_client_t /*ct2*/) *UokmsClient {
    obj := &UokmsClient {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*UokmsClient).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newUokmsClientCopy(ctx *C.vsce_uokms_client_t /*ct2*/) *UokmsClient {
    obj := &UokmsClient {
        cCtx: C.vsce_uokms_client_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*UokmsClient).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *UokmsClient) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *UokmsClient) delete() {
    C.vsce_uokms_client_delete(obj.cCtx)
}

/*
* Random used for key generation, proofs, etc.
*/
func (obj *UokmsClient) SetRandom(random foundation.Random) {
    C.vsce_uokms_client_release_random(obj.cCtx)
    C.vsce_uokms_client_use_random(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(random.Ctx())))

    runtime.KeepAlive(random)
    runtime.KeepAlive(obj)
}

/*
* Random used for crypto operations to make them const-time
*/
func (obj *UokmsClient) SetOperationRandom(operationRandom foundation.Random) {
    C.vsce_uokms_client_release_operation_random(obj.cCtx)
    C.vsce_uokms_client_use_operation_random(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(operationRandom.Ctx())))

    runtime.KeepAlive(operationRandom)
    runtime.KeepAlive(obj)
}

/*
* Setups dependencies with default values.
*/
func (obj *UokmsClient) SetupDefaults() error {
    proxyResult := /*pr4*/C.vsce_uokms_client_setup_defaults(obj.cCtx)

    err := PheErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    runtime.KeepAlive(obj)

    return nil
}

/*
* Sets client private and server public key
* Call this method before any other methods
* This function should be called only once
*/
func (obj *UokmsClient) SetKeys(clientPrivateKey []byte, serverPublicKey []byte) error {
    clientPrivateKeyData := helperWrapData (clientPrivateKey)
    serverPublicKeyData := helperWrapData (serverPublicKey)

    proxyResult := /*pr4*/C.vsce_uokms_client_set_keys(obj.cCtx, clientPrivateKeyData, serverPublicKeyData)

    err := PheErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    runtime.KeepAlive(obj)

    return nil
}

/*
* Generates client private key
*/
func (obj *UokmsClient) GenerateClientPrivateKey() ([]byte, error) {
    clientPrivateKeyBuf, clientPrivateKeyBufErr := bufferNewBuffer(int(PheCommonPhePrivateKeyLength /* lg4 */))
    if clientPrivateKeyBufErr != nil {
        return nil, clientPrivateKeyBufErr
    }
    defer clientPrivateKeyBuf.Delete()


    proxyResult := /*pr4*/C.vsce_uokms_client_generate_client_private_key(obj.cCtx, clientPrivateKeyBuf.ctx)

    err := PheErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return clientPrivateKeyBuf.getData() /* r7 */, nil
}

/*
* Generates new encrypt wrap (which should be stored and then used for decryption) + encryption key
* of "encryption key len" that can be used for symmetric encryption
*/
func (obj *UokmsClient) GenerateEncryptWrap(encryptionKeyLen uint) ([]byte, []byte, error) {
    wrapBuf, wrapBufErr := bufferNewBuffer(int(PheCommonPhePublicKeyLength /* lg4 */))
    if wrapBufErr != nil {
        return nil, nil, wrapBufErr
    }
    defer wrapBuf.Delete()

    encryptionKeyBuf, encryptionKeyBufErr := bufferNewBuffer(int(encryptionKeyLen))
    if encryptionKeyBufErr != nil {
        return nil, nil, encryptionKeyBufErr
    }
    defer encryptionKeyBuf.Delete()


    proxyResult := /*pr4*/C.vsce_uokms_client_generate_encrypt_wrap(obj.cCtx, wrapBuf.ctx, (C.size_t)(encryptionKeyLen)/*pa10*/, encryptionKeyBuf.ctx)

    err := PheErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, nil, err
    }

    runtime.KeepAlive(obj)

    return wrapBuf.getData() /* r7 */, encryptionKeyBuf.getData() /* r7 */, nil
}

/*
* Generates request to decrypt data, this request should be sent to the server.
* Server response is then passed to "process decrypt response" where encryption key can be decapsulated
*/
func (obj *UokmsClient) GenerateDecryptRequest(wrap []byte) ([]byte, []byte, error) {
    deblindFactorBuf, deblindFactorBufErr := bufferNewBuffer(int(PheCommonPhePrivateKeyLength /* lg4 */))
    if deblindFactorBufErr != nil {
        return nil, nil, deblindFactorBufErr
    }
    defer deblindFactorBuf.Delete()

    decryptRequestBuf, decryptRequestBufErr := bufferNewBuffer(int(PheCommonPhePublicKeyLength /* lg4 */))
    if decryptRequestBufErr != nil {
        return nil, nil, decryptRequestBufErr
    }
    defer decryptRequestBuf.Delete()
    wrapData := helperWrapData (wrap)

    proxyResult := /*pr4*/C.vsce_uokms_client_generate_decrypt_request(obj.cCtx, wrapData, deblindFactorBuf.ctx, decryptRequestBuf.ctx)

    err := PheErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, nil, err
    }

    runtime.KeepAlive(obj)

    return deblindFactorBuf.getData() /* r7 */, decryptRequestBuf.getData() /* r7 */, nil
}

/*
* Processed server response, checks server proof and decapsulates encryption key
*/
func (obj *UokmsClient) ProcessDecryptResponse(wrap []byte, decryptRequest []byte, decryptResponse []byte, deblindFactor []byte, encryptionKeyLen uint) ([]byte, error) {
    encryptionKeyBuf, encryptionKeyBufErr := bufferNewBuffer(int(encryptionKeyLen))
    if encryptionKeyBufErr != nil {
        return nil, encryptionKeyBufErr
    }
    defer encryptionKeyBuf.Delete()
    wrapData := helperWrapData (wrap)
    decryptRequestData := helperWrapData (decryptRequest)
    decryptResponseData := helperWrapData (decryptResponse)
    deblindFactorData := helperWrapData (deblindFactor)

    proxyResult := /*pr4*/C.vsce_uokms_client_process_decrypt_response(obj.cCtx, wrapData, decryptRequestData, decryptResponseData, deblindFactorData, (C.size_t)(encryptionKeyLen)/*pa10*/, encryptionKeyBuf.ctx)

    err := PheErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return encryptionKeyBuf.getData() /* r7 */, nil
}

/*
* Rotates client and server keys using given update token obtained from server
*/
func (obj *UokmsClient) RotateKeys(updateToken []byte) ([]byte, []byte, error) {
    newClientPrivateKeyBuf, newClientPrivateKeyBufErr := bufferNewBuffer(int(PheCommonPhePrivateKeyLength /* lg4 */))
    if newClientPrivateKeyBufErr != nil {
        return nil, nil, newClientPrivateKeyBufErr
    }
    defer newClientPrivateKeyBuf.Delete()

    newServerPublicKeyBuf, newServerPublicKeyBufErr := bufferNewBuffer(int(PheCommonPhePublicKeyLength /* lg4 */))
    if newServerPublicKeyBufErr != nil {
        return nil, nil, newServerPublicKeyBufErr
    }
    defer newServerPublicKeyBuf.Delete()
    updateTokenData := helperWrapData (updateToken)

    proxyResult := /*pr4*/C.vsce_uokms_client_rotate_keys(obj.cCtx, updateTokenData, newClientPrivateKeyBuf.ctx, newServerPublicKeyBuf.ctx)

    err := PheErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, nil, err
    }

    runtime.KeepAlive(obj)

    return newClientPrivateKeyBuf.getData() /* r7 */, newServerPublicKeyBuf.getData() /* r7 */, nil
}
