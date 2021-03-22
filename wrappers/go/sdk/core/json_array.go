package sdk_core

// #include <virgil/sdk/core/vssc_core_sdk_public.h>
import "C"
import unsafe "unsafe"
import "runtime"

/*
* Minimal JSON array.
* Currently only objects array are supported
 */
type JsonArray struct {
	cCtx *C.vssc_json_array_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *JsonArray) Ctx() uintptr {
	return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewJsonArray() *JsonArray {
	ctx := C.vssc_json_array_new()
	obj := &JsonArray{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*JsonArray).Delete)
	return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewJsonArrayWithCtx(anyctx interface{}) *JsonArray {
	ctx, ok := anyctx.(*C.vssc_json_array_t /*ct2*/)
	if !ok {
		return nil //TODO, &CoreSdkError{-1,"Cast error for struct JsonArray."}
	}
	obj := &JsonArray{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*JsonArray).Delete)
	return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewJsonArrayCopy(anyctx interface{}) *JsonArray {
	ctx, ok := anyctx.(*C.vssc_json_array_t /*ct2*/)
	if !ok {
		return nil //TODO, &CoreSdkError{-1,"Cast error for struct JsonArray."}
	}
	obj := &JsonArray{
		cCtx: C.vssc_json_array_shallow_copy(ctx),
	}
	runtime.SetFinalizer(obj, (*JsonArray).Delete)
	return obj
}

/*
* Release underlying C context.
 */
func (obj *JsonArray) Delete() {
	if obj == nil {
		return
	}
	runtime.SetFinalizer(obj, nil)
	obj.delete()
}

/*
* Release underlying C context.
 */
func (obj *JsonArray) delete() {
	C.vssc_json_array_delete(obj.cCtx)
}

/*
* Return how many objects an array handles.
 */
func (obj *JsonArray) Count() uint {
	proxyResult := /*pr4*/ C.vssc_json_array_count(obj.cCtx)

	runtime.KeepAlive(obj)

	return uint(proxyResult) /* r9 */
}

/*
* Add object value .
 */
func (obj *JsonArray) AddObjectValue(value *JsonObject) {
	C.vssc_json_array_add_object_value(obj.cCtx, (*C.vssc_json_object_t)(unsafe.Pointer(value.Ctx())))

	runtime.KeepAlive(obj)

	runtime.KeepAlive(value)

	return
}

/*
* Return a object value for a given index.
* Check array length before call this method.
 */
func (obj *JsonArray) GetObjectValue(index uint) (*JsonObject, error) {
	var error C.vssc_error_t
	C.vssc_error_reset(&error)

	proxyResult := /*pr4*/ C.vssc_json_array_get_object_value(obj.cCtx, (C.size_t)(index) /*pa10*/, &error)

	err := CoreSdkErrorHandleStatus(error.status)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(obj)

	return NewJsonObjectWithCtx(proxyResult) /* r6 */, nil
}

/*
* Add string value.
 */
func (obj *JsonArray) AddStringValue(value string) {
	valueChar := C.CString(value)
	defer C.free(unsafe.Pointer(valueChar))
	valueStr := C.vsc_str_from_str(valueChar)

	C.vssc_json_array_add_string_value(obj.cCtx, valueStr)

	runtime.KeepAlive(obj)

	runtime.KeepAlive(value)

	return
}

/*
* Return a string value for a given index.
* Check array length before call this method.
 */
func (obj *JsonArray) GetStringValue(index uint) (string, error) {
	var error C.vssc_error_t
	C.vssc_error_reset(&error)

	proxyResult := /*pr4*/ C.vssc_json_array_get_string_value(obj.cCtx, (C.size_t)(index) /*pa10*/, &error)

	err := CoreSdkErrorHandleStatus(error.status)
	if err != nil {
		return "", err
	}

	runtime.KeepAlive(obj)

	return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */, nil
}

/*
* Add string values from the given list.
 */
func (obj *JsonArray) AddStringValues(stringValues *StringList) {
	C.vssc_json_array_add_string_values(obj.cCtx, (*C.vssc_string_list_t)(unsafe.Pointer(stringValues.Ctx())))

	runtime.KeepAlive(obj)

	runtime.KeepAlive(stringValues)

	return
}

/*
* Return string values as list.
 */
func (obj *JsonArray) GetStringValues() (*StringList, error) {
	var error C.vssc_error_t
	C.vssc_error_reset(&error)

	proxyResult := /*pr4*/ C.vssc_json_array_get_string_values(obj.cCtx, &error)

	err := CoreSdkErrorHandleStatus(error.status)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(obj)

	return NewStringListWithCtx(proxyResult) /* r6 */, nil
}

/*
* Add number value.
 */
func (obj *JsonArray) AddNumberValue(value uint) {
	C.vssc_json_array_add_number_value(obj.cCtx, (C.size_t)(value) /*pa10*/)

	runtime.KeepAlive(obj)

	return
}

/*
* Return a number value for a given index.
* Check array length before call this method.
 */
func (obj *JsonArray) GetNumberValue(index uint) (uint, error) {
	var error C.vssc_error_t
	C.vssc_error_reset(&error)

	proxyResult := /*pr4*/ C.vssc_json_array_get_number_value(obj.cCtx, (C.size_t)(index) /*pa10*/, &error)

	err := CoreSdkErrorHandleStatus(error.status)
	if err != nil {
		return 0, err
	}

	runtime.KeepAlive(obj)

	return uint(proxyResult) /* r9 */, nil
}

/*
* Add number values from the given list.
 */
func (obj *JsonArray) AddNumberValues(numberValues *NumberList) {
	C.vssc_json_array_add_number_values(obj.cCtx, (*C.vssc_number_list_t)(unsafe.Pointer(numberValues.Ctx())))

	runtime.KeepAlive(obj)

	runtime.KeepAlive(numberValues)

	return
}

/*
* Return number values as list.
 */
func (obj *JsonArray) GetNumberValues() (*NumberList, error) {
	var error C.vssc_error_t
	C.vssc_error_reset(&error)

	proxyResult := /*pr4*/ C.vssc_json_array_get_number_values(obj.cCtx, &error)

	err := CoreSdkErrorHandleStatus(error.status)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(obj)

	return NewNumberListWithCtx(proxyResult) /* r6 */, nil
}

/*
* Return JSON body as string.
 */
func (obj *JsonArray) AsStr() string {
	proxyResult := /*pr4*/ C.vssc_json_array_as_str(obj.cCtx)

	runtime.KeepAlive(obj)

	return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */
}

/*
* Parse a given JSON string.
 */
func JsonArrayParse(json string) (*JsonArray, error) {
	var error C.vssc_error_t
	C.vssc_error_reset(&error)
	jsonChar := C.CString(json)
	defer C.free(unsafe.Pointer(jsonChar))
	jsonStr := C.vsc_str_from_str(jsonChar)

	proxyResult := /*pr4*/ C.vssc_json_array_parse(jsonStr, &error)

	err := CoreSdkErrorHandleStatus(error.status)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(json)

	return NewJsonArrayWithCtx(proxyResult) /* r6 */, nil
}
