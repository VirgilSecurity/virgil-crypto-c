package sdk_comm_kit

// #include <virgil/sdk/comm-kit/vssq_comm_kit_public.h>
import "C"
import unsafe "unsafe"
import "runtime"
import foundation "virgil/foundation"

/*
* File encryption and decryption to be used with the Cloud FS.
 */
type MessengerCloudFsCipher struct {
	cCtx *C.vssq_messenger_cloud_fs_cipher_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *MessengerCloudFsCipher) Ctx() uintptr {
	return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewMessengerCloudFsCipher() *MessengerCloudFsCipher {
	ctx := C.vssq_messenger_cloud_fs_cipher_new()
	obj := &MessengerCloudFsCipher{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*MessengerCloudFsCipher).Delete)
	return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewMessengerCloudFsCipherWithCtx(anyctx interface{}) *MessengerCloudFsCipher {
	ctx, ok := anyctx.(*C.vssq_messenger_cloud_fs_cipher_t /*ct2*/)
	if !ok {
		return nil //TODO, &CommKitError{-1,"Cast error for struct MessengerCloudFsCipher."}
	}
	obj := &MessengerCloudFsCipher{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*MessengerCloudFsCipher).Delete)
	return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewMessengerCloudFsCipherCopy(anyctx interface{}) *MessengerCloudFsCipher {
	ctx, ok := anyctx.(*C.vssq_messenger_cloud_fs_cipher_t /*ct2*/)
	if !ok {
		return nil //TODO, &CommKitError{-1,"Cast error for struct MessengerCloudFsCipher."}
	}
	obj := &MessengerCloudFsCipher{
		cCtx: C.vssq_messenger_cloud_fs_cipher_shallow_copy(ctx),
	}
	runtime.SetFinalizer(obj, (*MessengerCloudFsCipher).Delete)
	return obj
}

/*
* Release underlying C context.
 */
func (obj *MessengerCloudFsCipher) Delete() {
	if obj == nil {
		return
	}
	runtime.SetFinalizer(obj, nil)
	obj.delete()
}

/*
* Release underlying C context.
 */
func (obj *MessengerCloudFsCipher) delete() {
	C.vssq_messenger_cloud_fs_cipher_delete(obj.cCtx)
}

func (obj *MessengerCloudFsCipher) SetRandom(random foundation.Random) {
	C.vssq_messenger_cloud_fs_cipher_release_random(obj.cCtx)
	C.vssq_messenger_cloud_fs_cipher_use_random(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(random.Ctx())))

	runtime.KeepAlive(random)
	runtime.KeepAlive(obj)
}

/*
* Setup predefined values to the uninitialized class dependencies.
 */
func (obj *MessengerCloudFsCipher) SetupDefaults() error {
	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_cipher_setup_defaults(obj.cCtx)

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
func (obj *MessengerCloudFsCipher) InitEncryptionOutKeyLen() uint {
	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_cipher_init_encryption_out_key_len(obj.cCtx)

	runtime.KeepAlive(obj)

	return uint(proxyResult) /* r9 */
}

/*
* Encryption initialization.
 */
func (obj *MessengerCloudFsCipher) InitEncryption(ownerPrivateKey foundation.PublicKey, dataLen uint) ([]byte, error) {
	outKeyBuf, outKeyBufErr := newBuffer(int(obj.InitEncryptionOutKeyLen() /* lg2 */))
	if outKeyBufErr != nil {
		return nil, outKeyBufErr
	}
	defer outKeyBuf.delete()

	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_cipher_init_encryption(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(ownerPrivateKey.Ctx())), (C.size_t)(dataLen) /*pa10*/, outKeyBuf.ctx)

	err := CommKitErrorHandleStatus(proxyResult)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(ownerPrivateKey)

	return outKeyBuf.getData() /* r7 */, nil
}

/*
* Return encryption header length.
 */
func (obj *MessengerCloudFsCipher) StartEncryptionOutLen() uint {
	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_cipher_start_encryption_out_len(obj.cCtx)

	runtime.KeepAlive(obj)

	return uint(proxyResult) /* r9 */
}

/*
* Start encryption and return header.
 */
func (obj *MessengerCloudFsCipher) StartEncryption() ([]byte, error) {
	outBuf, outBufErr := newBuffer(int(obj.StartEncryptionOutLen() /* lg2 */))
	if outBufErr != nil {
		return nil, outBufErr
	}
	defer outBuf.delete()

	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_cipher_start_encryption(obj.cCtx, outBuf.ctx)

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
func (obj *MessengerCloudFsCipher) ProcessEncryptionOutLen(dataLen uint) uint {
	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_cipher_process_encryption_out_len(obj.cCtx, (C.size_t)(dataLen) /*pa10*/)

	runtime.KeepAlive(obj)

	return uint(proxyResult) /* r9 */
}

/*
* Encrypt data and return encrypted buffer.
 */
func (obj *MessengerCloudFsCipher) ProcessEncryption(data []byte) ([]byte, error) {
	outBuf, outBufErr := newBuffer(int(obj.ProcessEncryptionOutLen(uint(len(data))) /* lg2 */))
	if outBufErr != nil {
		return nil, outBufErr
	}
	defer outBuf.delete()
	dataData := helperWrapData(data)

	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_cipher_process_encryption(obj.cCtx, dataData, outBuf.ctx)

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
func (obj *MessengerCloudFsCipher) FinishEncryptionOutLen() uint {
	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_cipher_finish_encryption_out_len(obj.cCtx)

	runtime.KeepAlive(obj)

	return uint(proxyResult) /* r9 */
}

/*
* Finish encryption and return last part of data.
 */
func (obj *MessengerCloudFsCipher) FinishEncryption() ([]byte, error) {
	outBuf, outBufErr := newBuffer(int(obj.FinishEncryptionOutLen() /* lg2 */))
	if outBufErr != nil {
		return nil, outBufErr
	}
	defer outBuf.delete()

	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_cipher_finish_encryption(obj.cCtx, outBuf.ctx)

	err := CommKitErrorHandleStatus(proxyResult)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(obj)

	return outBuf.getData() /* r7 */, nil
}

/*
* Return encryption footer length.
 */
func (obj *MessengerCloudFsCipher) FinishEncryptionFooterOutLen() uint {
	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_cipher_finish_encryption_footer_out_len(obj.cCtx)

	runtime.KeepAlive(obj)

	return uint(proxyResult) /* r9 */
}

/*
* Finish encryption and return footer data.
 */
func (obj *MessengerCloudFsCipher) FinishEncryptionFooter() ([]byte, error) {
	outBuf, outBufErr := newBuffer(int(obj.FinishEncryptionFooterOutLen() /* lg2 */))
	if outBufErr != nil {
		return nil, outBufErr
	}
	defer outBuf.delete()

	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_cipher_finish_encryption_footer(obj.cCtx, outBuf.ctx)

	err := CommKitErrorHandleStatus(proxyResult)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(obj)

	return outBuf.getData() /* r7 */, nil
}

/*
* Start decryption (Input - file encryption key).
 */
func (obj *MessengerCloudFsCipher) StartDecryption(key []byte) error {
	keyData := helperWrapData(key)

	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_cipher_start_decryption(obj.cCtx, keyData)

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
func (obj *MessengerCloudFsCipher) ProcessDecryptionOutLen(dataLen uint) uint {
	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_cipher_process_decryption_out_len(obj.cCtx, (C.size_t)(dataLen) /*pa10*/)

	runtime.KeepAlive(obj)

	return uint(proxyResult) /* r9 */
}

/*
* Decryption process.
 */
func (obj *MessengerCloudFsCipher) ProcessDecryption(data []byte) ([]byte, error) {
	outBuf, outBufErr := newBuffer(int(obj.ProcessDecryptionOutLen(uint(len(data))) /* lg2 */))
	if outBufErr != nil {
		return nil, outBufErr
	}
	defer outBuf.delete()
	dataData := helperWrapData(data)

	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_cipher_process_decryption(obj.cCtx, dataData, outBuf.ctx)

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
func (obj *MessengerCloudFsCipher) FinishDecryptionOutLen() uint {
	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_cipher_finish_decryption_out_len(obj.cCtx)

	runtime.KeepAlive(obj)

	return uint(proxyResult) /* r9 */
}

/*
* Finish decryption and check sign.
 */
func (obj *MessengerCloudFsCipher) FinishDecryption(ownerPublicKey foundation.PublicKey) ([]byte, error) {
	outBuf, outBufErr := newBuffer(int(obj.FinishDecryptionOutLen() /* lg2 */))
	if outBufErr != nil {
		return nil, outBufErr
	}
	defer outBuf.delete()

	proxyResult := /*pr4*/ C.vssq_messenger_cloud_fs_cipher_finish_decryption(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(ownerPublicKey.Ctx())), outBuf.ctx)

	err := CommKitErrorHandleStatus(proxyResult)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(ownerPublicKey)

	return outBuf.getData() /* r7 */, nil
}
