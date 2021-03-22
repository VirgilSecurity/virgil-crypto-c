package sdk_core

// #include <virgil/sdk/core/vssc_core_sdk_public.h>
import "C"
import unsafe "unsafe"
import "runtime"
import foundation "virgil/foundation"

/*
* Handles public key or private key and it's identifier.
*
* Note, that public key identifier equals to the private key identifier.
* Note, a key identifier can be calculated with "key provider" class from the foundation library.
 */
type KeyHandler struct {
	cCtx *C.vssc_key_handler_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *KeyHandler) Ctx() uintptr {
	return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewKeyHandler() *KeyHandler {
	ctx := C.vssc_key_handler_new()
	obj := &KeyHandler{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*KeyHandler).Delete)
	return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewKeyHandlerWithCtx(anyctx interface{}) *KeyHandler {
	ctx, ok := anyctx.(*C.vssc_key_handler_t /*ct2*/)
	if !ok {
		return nil //TODO, &CoreSdkError{-1,"Cast error for struct KeyHandler."}
	}
	obj := &KeyHandler{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*KeyHandler).Delete)
	return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewKeyHandlerCopy(anyctx interface{}) *KeyHandler {
	ctx, ok := anyctx.(*C.vssc_key_handler_t /*ct2*/)
	if !ok {
		return nil //TODO, &CoreSdkError{-1,"Cast error for struct KeyHandler."}
	}
	obj := &KeyHandler{
		cCtx: C.vssc_key_handler_shallow_copy(ctx),
	}
	runtime.SetFinalizer(obj, (*KeyHandler).Delete)
	return obj
}

/*
* Release underlying C context.
 */
func (obj *KeyHandler) Delete() {
	if obj == nil {
		return
	}
	runtime.SetFinalizer(obj, nil)
	obj.delete()
}

/*
* Release underlying C context.
 */
func (obj *KeyHandler) delete() {
	C.vssc_key_handler_delete(obj.cCtx)
}

/*
* Constructor.
 */
func NewKeyHandlerWith(identity string, keyId []byte, key foundation.Key) *KeyHandler {
	identityChar := C.CString(identity)
	defer C.free(unsafe.Pointer(identityChar))
	identityStr := C.vsc_str_from_str(identityChar)
	keyIdData := helperWrapData(keyId)

	proxyResult := /*pr4*/ C.vssc_key_handler_new_with(identityStr, keyIdData, (*C.vscf_impl_t)(unsafe.Pointer(key.Ctx())))

	runtime.KeepAlive(identity)

	runtime.KeepAlive(key)

	obj := &KeyHandler{
		cCtx: proxyResult,
	}
	runtime.SetFinalizer(obj, (*KeyHandler).Delete)
	return obj
}

/*
* Return user's identity associated with the key.
 */
func (obj *KeyHandler) Identity() string {
	proxyResult := /*pr4*/ C.vssc_key_handler_identity(obj.cCtx)

	runtime.KeepAlive(obj)

	return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */
}

/*
* Return public key identifier regardless of the underlying key - public or private.
 */
func (obj *KeyHandler) KeyId() []byte {
	proxyResult := /*pr4*/ C.vssc_key_handler_key_id(obj.cCtx)

	runtime.KeepAlive(obj)

	return helperExtractData(proxyResult) /* r1 */
}

/*
* Return key.
 */
func (obj *KeyHandler) Key() (foundation.Key, error) {
	proxyResult := /*pr4*/ C.vssc_key_handler_key(obj.cCtx)

	runtime.KeepAlive(obj)

	return foundation.ImplementationWrapKeyCopy(proxyResult) /* r4.1 */
}
