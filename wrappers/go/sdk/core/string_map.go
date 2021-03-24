package sdk_core

// #include <virgil/sdk/core/vssc_core_sdk_public.h>
import "C"
import unsafe "unsafe"
import "runtime"

/*
* Handles a map: key=string, value=string.
 */
type StringMap struct {
	cCtx *C.vssc_string_map_t /*ct2*/
}

const (
	StringMapCapacityMax uint = 1024 * 1024
)

/* Handle underlying C context. */
func (obj *StringMap) Ctx() uintptr {
	return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewStringMap() *StringMap {
	ctx := C.vssc_string_map_new()
	obj := &StringMap{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*StringMap).Delete)
	return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewStringMapWithCtx(pointer unsafe.Pointer) *StringMap {
	ctx := (*C.vssc_string_map_t /*ct2*/)(pointer)
	obj := &StringMap{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*StringMap).Delete)
	return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewStringMapCopy(pointer unsafe.Pointer) *StringMap {
	ctx := (*C.vssc_string_map_t /*ct2*/)(pointer)
	obj := &StringMap{
		cCtx: C.vssc_string_map_shallow_copy(ctx),
	}
	runtime.SetFinalizer(obj, (*StringMap).Delete)
	return obj
}

/*
* Release underlying C context.
 */
func (obj *StringMap) Delete() {
	if obj == nil {
		return
	}
	runtime.SetFinalizer(obj, nil)
	obj.delete()
}

/*
* Release underlying C context.
 */
func (obj *StringMap) delete() {
	C.vssc_string_map_delete(obj.cCtx)
}

/*
* Create an optimal map.
 */
func NewStringMapWithCapacity(capacity uint) *StringMap {
	proxyResult := /*pr4*/ C.vssc_string_map_new_with_capacity((C.size_t)(capacity) /*pa10*/)

	obj := &StringMap{
		cCtx: proxyResult,
	}
	runtime.SetFinalizer(obj, (*StringMap).Delete)
	return obj
}

/*
* Return map's capacity.
 */
func (obj *StringMap) Capacity() uint {
	proxyResult := /*pr4*/ C.vssc_string_map_capacity(obj.cCtx)

	runtime.KeepAlive(obj)

	return uint(proxyResult) /* r9 */
}

/*
* Put a new pair to the map.
 */
func (obj *StringMap) Put(key string, value string) {
	keyChar := C.CString(key)
	defer C.free(unsafe.Pointer(keyChar))
	keyStr := C.vsc_str_from_str(keyChar)
	valueChar := C.CString(value)
	defer C.free(unsafe.Pointer(valueChar))
	valueStr := C.vsc_str_from_str(valueChar)

	C.vssc_string_map_put(obj.cCtx, keyStr, valueStr)

	runtime.KeepAlive(obj)

	runtime.KeepAlive(key)

	runtime.KeepAlive(value)

	return
}

/*
* Return a value of the given key, or error.
 */
func (obj *StringMap) Get(key string) (string, error) {
	var error C.vssc_error_t
	C.vssc_error_reset(&error)
	keyChar := C.CString(key)
	defer C.free(unsafe.Pointer(keyChar))
	keyStr := C.vsc_str_from_str(keyChar)

	proxyResult := /*pr4*/ C.vssc_string_map_get(obj.cCtx, keyStr, &error)

	err := CoreSdkErrorHandleStatus(error.status)
	if err != nil {
		return "", err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(key)

	return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */, nil
}

/*
* Return a value of the given key, or error.
 */
func (obj *StringMap) GetInner(key string) (string, error) {
	var error C.vssc_error_t
	C.vssc_error_reset(&error)
	keyChar := C.CString(key)
	defer C.free(unsafe.Pointer(keyChar))
	keyStr := C.vsc_str_from_str(keyChar)

	proxyResult := /*pr4*/ C.vssc_string_map_get_inner(obj.cCtx, keyStr, &error)

	err := CoreSdkErrorHandleStatus(error.status)
	if err != nil {
		return "", err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(key)

	return C.GoString(C.vsc_str_buffer_chars(proxyResult)) /* r2.1 */, nil
}

/*
* Return true if value of the given key exists.
 */
func (obj *StringMap) Contains(key string) bool {
	keyChar := C.CString(key)
	defer C.free(unsafe.Pointer(keyChar))
	keyStr := C.vsc_str_from_str(keyChar)

	proxyResult := /*pr4*/ C.vssc_string_map_contains(obj.cCtx, keyStr)

	runtime.KeepAlive(obj)

	runtime.KeepAlive(key)

	return bool(proxyResult) /* r9 */
}

/*
* Return map keys.
 */
func (obj *StringMap) Keys() *StringList {
	proxyResult := /*pr4*/ C.vssc_string_map_keys(obj.cCtx)

	runtime.KeepAlive(obj)

	return NewStringListWithCtx(unsafe.Pointer(proxyResult)) /* r6 */
}

/*
* Return map values.
 */
func (obj *StringMap) Values() *StringList {
	proxyResult := /*pr4*/ C.vssc_string_map_values(obj.cCtx)

	runtime.KeepAlive(obj)

	return NewStringListWithCtx(unsafe.Pointer(proxyResult)) /* r6 */
}

/*
* Return a new map with all keys and it values being swapped.
 */
func (obj *StringMap) SwapKeyValues() *StringMap {
	proxyResult := /*pr4*/ C.vssc_string_map_swap_key_values(obj.cCtx)

	runtime.KeepAlive(obj)

	return NewStringMapWithCtx(unsafe.Pointer(proxyResult)) /* r6 */
}
