package sdk_core

// #include <virgil/sdk/core/vssc_core_sdk_public.h>
import "C"
import unsafe "unsafe"
import "runtime"

/*
* Minimal JSON object.
 */
type JsonObject struct {
	cCtx *C.vssc_json_object_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *JsonObject) Ctx() uintptr {
	return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewJsonObject() *JsonObject {
	ctx := C.vssc_json_object_new()
	obj := &JsonObject{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*JsonObject).Delete)
	return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewJsonObjectWithCtx(anyctx interface{}) *JsonObject {
	ctx, ok := anyctx.(*C.vssc_json_object_t /*ct2*/)
	if !ok {
		return nil //TODO, &CoreSdkError{-1,"Cast error for struct JsonObject."}
	}
	obj := &JsonObject{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*JsonObject).Delete)
	return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewJsonObjectCopy(anyctx interface{}) *JsonObject {
	ctx, ok := anyctx.(*C.vssc_json_object_t /*ct2*/)
	if !ok {
		return nil //TODO, &CoreSdkError{-1,"Cast error for struct JsonObject."}
	}
	obj := &JsonObject{
		cCtx: C.vssc_json_object_shallow_copy(ctx),
	}
	runtime.SetFinalizer(obj, (*JsonObject).Delete)
	return obj
}

/*
* Release underlying C context.
 */
func (obj *JsonObject) Delete() {
	if obj == nil {
		return
	}
	runtime.SetFinalizer(obj, nil)
	obj.delete()
}

/*
* Release underlying C context.
 */
func (obj *JsonObject) delete() {
	C.vssc_json_object_delete(obj.cCtx)
}

/*
* Return true if object has no fields.
 */
func (obj *JsonObject) IsEmpty() bool {
	proxyResult := /*pr4*/ C.vssc_json_object_is_empty(obj.cCtx)

	runtime.KeepAlive(obj)

	return bool(proxyResult) /* r9 */
}

/*
* Add string value with a given key.
 */
func (obj *JsonObject) AddStringValue(key string, value string) {
	keyChar := C.CString(key)
	defer C.free(unsafe.Pointer(keyChar))
	keyStr := C.vsc_str_from_str(keyChar)
	valueChar := C.CString(value)
	defer C.free(unsafe.Pointer(valueChar))
	valueStr := C.vsc_str_from_str(valueChar)

	C.vssc_json_object_add_string_value(obj.cCtx, keyStr, valueStr)

	runtime.KeepAlive(obj)

	runtime.KeepAlive(key)

	runtime.KeepAlive(value)

	return
}

/*
* Return a string value for a given key.
* Return error, if given key is not found or type mismatch.
 */
func (obj *JsonObject) GetStringValue(key string) (string, error) {
	var error C.vssc_error_t
	C.vssc_error_reset(&error)
	keyChar := C.CString(key)
	defer C.free(unsafe.Pointer(keyChar))
	keyStr := C.vsc_str_from_str(keyChar)

	proxyResult := /*pr4*/ C.vssc_json_object_get_string_value(obj.cCtx, keyStr, &error)

	err := CoreSdkErrorHandleStatus(error.status)
	if err != nil {
		return "", err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(key)

	return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */, nil
}

/*
* Add binary value with a given key.
* Given binary value is base64 encoded first
 */
func (obj *JsonObject) AddBinaryValue(key string, value []byte) {
	keyChar := C.CString(key)
	defer C.free(unsafe.Pointer(keyChar))
	keyStr := C.vsc_str_from_str(keyChar)
	valueData := helperWrapData(value)

	C.vssc_json_object_add_binary_value(obj.cCtx, keyStr, valueData)

	runtime.KeepAlive(obj)

	runtime.KeepAlive(key)

	return
}

/*
* Return buffer length required to hold a binary value for a given key.
* Returns 0, if given key is not found or type mismatch.
 */
func (obj *JsonObject) GetBinaryValueLen(key string) uint {
	keyChar := C.CString(key)
	defer C.free(unsafe.Pointer(keyChar))
	keyStr := C.vsc_str_from_str(keyChar)

	proxyResult := /*pr4*/ C.vssc_json_object_get_binary_value_len(obj.cCtx, keyStr)

	runtime.KeepAlive(obj)

	runtime.KeepAlive(key)

	return uint(proxyResult) /* r9 */
}

/*
* Return a binary value for a given key.
* Return error, if given key is not found or type mismatch.
* Return error, if base64 decode failed.
 */
func (obj *JsonObject) GetBinaryValue(key string) ([]byte, error) {
	keyChar := C.CString(key)
	defer C.free(unsafe.Pointer(keyChar))
	keyStr := C.vsc_str_from_str(keyChar)

	valueBuf, valueBufErr := newBuffer(int(obj.GetBinaryValueLen(key) /* lg2 */))
	if valueBufErr != nil {
		return nil, valueBufErr
	}
	defer valueBuf.delete()

	proxyResult := /*pr4*/ C.vssc_json_object_get_binary_value(obj.cCtx, keyStr, valueBuf.ctx)

	err := CoreSdkErrorHandleStatus(proxyResult)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(key)

	return valueBuf.getData() /* r7 */, nil
}

/*
* Add integer value with a given key.
 */
func (obj *JsonObject) AddIntValue(key string, value int32) {
	keyChar := C.CString(key)
	defer C.free(unsafe.Pointer(keyChar))
	keyStr := C.vsc_str_from_str(keyChar)

	C.vssc_json_object_add_int_value(obj.cCtx, keyStr, (C.int32_t)(value) /*pa10*/)

	runtime.KeepAlive(obj)

	runtime.KeepAlive(key)

	return
}

/*
* Return an integer value for a given key.
* Return error, if given key is not found or type mismatch.
 */
func (obj *JsonObject) GetIntValue(key string) (int32, error) {
	var error C.vssc_error_t
	C.vssc_error_reset(&error)
	keyChar := C.CString(key)
	defer C.free(unsafe.Pointer(keyChar))
	keyStr := C.vsc_str_from_str(keyChar)

	proxyResult := /*pr4*/ C.vssc_json_object_get_int_value(obj.cCtx, keyStr, &error)

	err := CoreSdkErrorHandleStatus(error.status)
	if err != nil {
		return 0, err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(key)

	return int32(proxyResult) /* r9 */, nil
}

/*
* Add object value with a given key.
 */
func (obj *JsonObject) AddObjectValue(key string, value *JsonObject) {
	keyChar := C.CString(key)
	defer C.free(unsafe.Pointer(keyChar))
	keyStr := C.vsc_str_from_str(keyChar)

	C.vssc_json_object_add_object_value(obj.cCtx, keyStr, (*C.vssc_json_object_t)(unsafe.Pointer(value.Ctx())))

	runtime.KeepAlive(obj)

	runtime.KeepAlive(key)

	runtime.KeepAlive(value)

	return
}

/*
* Return an object value for a given key.
* Return error, if given key is not found or type mismatch.
 */
func (obj *JsonObject) GetObjectValue(key string) (*JsonObject, error) {
	var error C.vssc_error_t
	C.vssc_error_reset(&error)
	keyChar := C.CString(key)
	defer C.free(unsafe.Pointer(keyChar))
	keyStr := C.vsc_str_from_str(keyChar)

	proxyResult := /*pr4*/ C.vssc_json_object_get_object_value(obj.cCtx, keyStr, &error)

	err := CoreSdkErrorHandleStatus(error.status)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(key)

	return NewJsonObjectWithCtx(proxyResult) /* r6 */, nil
}

/*
* Add array value with a given key.
 */
func (obj *JsonObject) AddArrayValue(key string, value *JsonArray) {
	keyChar := C.CString(key)
	defer C.free(unsafe.Pointer(keyChar))
	keyStr := C.vsc_str_from_str(keyChar)

	C.vssc_json_object_add_array_value(obj.cCtx, keyStr, (*C.vssc_json_array_t)(unsafe.Pointer(value.Ctx())))

	runtime.KeepAlive(obj)

	runtime.KeepAlive(key)

	runtime.KeepAlive(value)

	return
}

/*
* Return an array value for a given key.
* Return error, if given key is not found or type mismatch.
 */
func (obj *JsonObject) GetArrayValue(key string) (*JsonArray, error) {
	var error C.vssc_error_t
	C.vssc_error_reset(&error)
	keyChar := C.CString(key)
	defer C.free(unsafe.Pointer(keyChar))
	keyStr := C.vsc_str_from_str(keyChar)

	proxyResult := /*pr4*/ C.vssc_json_object_get_array_value(obj.cCtx, keyStr, &error)

	err := CoreSdkErrorHandleStatus(error.status)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(key)

	return NewJsonArrayWithCtx(proxyResult) /* r6 */, nil
}

/*
* Return JSON body as string.
 */
func (obj *JsonObject) AsStr() string {
	proxyResult := /*pr4*/ C.vssc_json_object_as_str(obj.cCtx)

	runtime.KeepAlive(obj)

	return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */
}

/*
* Return JSON object as string map key->value.
* Return error, if at least one value is not a string.
 */
func (obj *JsonObject) AsStringMap() (*StringMap, error) {
	var error C.vssc_error_t
	C.vssc_error_reset(&error)

	proxyResult := /*pr4*/ C.vssc_json_object_as_string_map(obj.cCtx, &error)

	err := CoreSdkErrorHandleStatus(error.status)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(obj)

	return NewStringMapWithCtx(proxyResult) /* r6 */, nil
}

/*
* Parse a given JSON string.
 */
func JsonObjectParse(json string) (*JsonObject, error) {
	var error C.vssc_error_t
	C.vssc_error_reset(&error)
	jsonChar := C.CString(json)
	defer C.free(unsafe.Pointer(jsonChar))
	jsonStr := C.vsc_str_from_str(jsonChar)

	proxyResult := /*pr4*/ C.vssc_json_object_parse(jsonStr, &error)

	err := CoreSdkErrorHandleStatus(error.status)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(json)

	return NewJsonObjectWithCtx(proxyResult) /* r6 */, nil
}
