package sdk_comm_kit

// #include <virgil/sdk/comm-kit/vssq_comm_kit_public.h>
import "C"
import unsafe "unsafe"
import "runtime"
import foundation "virgil/foundation"


/*
* Segment file encryption and decryption.
*/
type MessengerFileCipher struct {
    cCtx *C.vssq_messenger_file_cipher_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *MessengerFileCipher) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewMessengerFileCipher() *MessengerFileCipher {
    ctx := C.vssq_messenger_file_cipher_new()
    obj := &MessengerFileCipher {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*MessengerFileCipher).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewMessengerFileCipherWithCtx(pointer unsafe.Pointer) *MessengerFileCipher {
    ctx := (*C.vssq_messenger_file_cipher_t /*ct2*/)(pointer)
    obj := &MessengerFileCipher {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*MessengerFileCipher).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewMessengerFileCipherCopy(pointer unsafe.Pointer) *MessengerFileCipher {
    ctx := (*C.vssq_messenger_file_cipher_t /*ct2*/)(pointer)
    obj := &MessengerFileCipher {
        cCtx: C.vssq_messenger_file_cipher_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*MessengerFileCipher).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *MessengerFileCipher) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *MessengerFileCipher) delete() {
    C.vssq_messenger_file_cipher_delete(obj.cCtx)
}

func (obj *MessengerFileCipher) SetRandom(random foundation.Random) {
    C.vssq_messenger_file_cipher_release_random(obj.cCtx)
    C.vssq_messenger_file_cipher_use_random(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(random.Ctx())))

    runtime.KeepAlive(random)
    runtime.KeepAlive(obj)
}

/*
* Setup predefined values to the uninitialized class dependencies.
*/
func (obj *MessengerFileCipher) SetupDefaults() error {
    proxyResult := /*pr4*/C.vssq_messenger_file_cipher_setup_defaults(obj.cCtx)

    err := CommKitErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    runtime.KeepAlive(obj)

    return nil
}

/*
* Return key length for encrypt file.
*/
func (obj *MessengerFileCipher) InitEncryptionOutKeyLen() uint {
    proxyResult := /*pr4*/C.vssq_messenger_file_cipher_init_encryption_out_key_len(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Encryption initialization.
*/
func (obj *MessengerFileCipher) InitEncryption() ([]byte, error) {
    outKeyBuf, outKeyBufErr := newBuffer(int(obj.InitEncryptionOutKeyLen() /* lg2 */))
    if outKeyBufErr != nil {
        return nil, outKeyBufErr
    }
    defer outKeyBuf.delete()


    proxyResult := /*pr4*/C.vssq_messenger_file_cipher_init_encryption(obj.cCtx, outKeyBuf.ctx)

    err := CommKitErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return outKeyBuf.getData() /* r7 */, nil
}

/*
* Return encryption header length.
*/
func (obj *MessengerFileCipher) StartEncryptionOutLen() uint {
    proxyResult := /*pr4*/C.vssq_messenger_file_cipher_start_encryption_out_len(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Start encryption and return header.
*/
func (obj *MessengerFileCipher) StartEncryption() ([]byte, error) {
    outBuf, outBufErr := newBuffer(int(obj.StartEncryptionOutLen() /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.delete()


    proxyResult := /*pr4*/C.vssq_messenger_file_cipher_start_encryption(obj.cCtx, outBuf.ctx)

    err := CommKitErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return outBuf.getData() /* r7 */, nil
}

/*
* Return encryption process output buffer length.
*/
func (obj *MessengerFileCipher) ProcessEncryptionOutLen(dataLen uint) uint {
    proxyResult := /*pr4*/C.vssq_messenger_file_cipher_process_encryption_out_len(obj.cCtx, (C.size_t)(dataLen)/*pa10*/)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Encrypt data and return encrypted buffer.
*/
func (obj *MessengerFileCipher) ProcessEncryption(data []byte) ([]byte, error) {
    outBuf, outBufErr := newBuffer(int(obj.ProcessEncryptionOutLen(uint(len(data))) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.delete()
    dataData := helperWrapData (data)

    proxyResult := /*pr4*/C.vssq_messenger_file_cipher_process_encryption(obj.cCtx, dataData, outBuf.ctx)

    err := CommKitErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return outBuf.getData() /* r7 */, nil
}

/*
* Return finish encryption data length.
*/
func (obj *MessengerFileCipher) FinishEncryptionOutLen() uint {
    proxyResult := /*pr4*/C.vssq_messenger_file_cipher_finish_encryption_out_len(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Return finish encryption data length.
*/
func (obj *MessengerFileCipher) FinishEncryptionSignatureLen(signerPrivateKey foundation.PrivateKey) uint {
    proxyResult := /*pr4*/C.vssq_messenger_file_cipher_finish_encryption_signature_len(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(signerPrivateKey.Ctx())))

    runtime.KeepAlive(obj)

    runtime.KeepAlive(signerPrivateKey)

    return uint(proxyResult) /* r9 */
}

/*
* Finish encryption and return last part of data.
* Also signature is returned.
*/
func (obj *MessengerFileCipher) FinishEncryption(signerPrivateKey foundation.PrivateKey) ([]byte, []byte, error) {
    outBuf, outBufErr := newBuffer(int(obj.FinishEncryptionOutLen() /* lg2 */))
    if outBufErr != nil {
        return nil, nil, outBufErr
    }
    defer outBuf.delete()

    signatureBuf, signatureBufErr := newBuffer(int(obj.FinishEncryptionSignatureLen(signerPrivateKey. (foundation.PrivateKey) /* lg0 */) /* lg2 */))
    if signatureBufErr != nil {
        return nil, nil, signatureBufErr
    }
    defer signatureBuf.delete()


    proxyResult := /*pr4*/C.vssq_messenger_file_cipher_finish_encryption(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(signerPrivateKey.Ctx())), outBuf.ctx, signatureBuf.ctx)

    err := CommKitErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(signerPrivateKey)

    return outBuf.getData() /* r7 */, signatureBuf.getData() /* r7 */, nil
}

/*
* Start decryption with a key generated during encryption and signature.
*/
func (obj *MessengerFileCipher) StartDecryption(key []byte, signature []byte) error {
    keyData := helperWrapData (key)
    signatureData := helperWrapData (signature)

    proxyResult := /*pr4*/C.vssq_messenger_file_cipher_start_decryption(obj.cCtx, keyData, signatureData)

    err := CommKitErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    runtime.KeepAlive(obj)

    return nil
}

/*
* Return decryption data length.
*/
func (obj *MessengerFileCipher) ProcessDecryptionOutLen(dataLen uint) uint {
    proxyResult := /*pr4*/C.vssq_messenger_file_cipher_process_decryption_out_len(obj.cCtx, (C.size_t)(dataLen)/*pa10*/)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Decryption process.
*/
func (obj *MessengerFileCipher) ProcessDecryption(data []byte) ([]byte, error) {
    outBuf, outBufErr := newBuffer(int(obj.ProcessDecryptionOutLen(uint(len(data))) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.delete()
    dataData := helperWrapData (data)

    proxyResult := /*pr4*/C.vssq_messenger_file_cipher_process_decryption(obj.cCtx, dataData, outBuf.ctx)

    err := CommKitErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return outBuf.getData() /* r7 */, nil
}

/*
* Return finish data part length.
*/
func (obj *MessengerFileCipher) FinishDecryptionOutLen() uint {
    proxyResult := /*pr4*/C.vssq_messenger_file_cipher_finish_decryption_out_len(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Finish decryption and check signature.
*/
func (obj *MessengerFileCipher) FinishDecryption(signerPublicKey foundation.PublicKey) ([]byte, error) {
    outBuf, outBufErr := newBuffer(int(obj.FinishDecryptionOutLen() /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.delete()


    proxyResult := /*pr4*/C.vssq_messenger_file_cipher_finish_decryption(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(signerPublicKey.Ctx())), outBuf.ctx)

    err := CommKitErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(signerPublicKey)

    return outBuf.getData() /* r7 */, nil
}
