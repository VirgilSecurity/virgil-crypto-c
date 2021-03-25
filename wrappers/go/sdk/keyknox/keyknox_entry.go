package sdk_keyknox

// #include <virgil/sdk/keyknox/vssk_keyknox_sdk_public.h>
import "C"
import unsafe "unsafe"
import "runtime"
import sdk_core "virgil/sdk/core"


/*
* A new or stored record within the Virgil Keyknox Service.
*/
type KeyknoxEntry struct {
    cCtx *C.vssk_keyknox_entry_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *KeyknoxEntry) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewKeyknoxEntry() *KeyknoxEntry {
    ctx := C.vssk_keyknox_entry_new()
    obj := &KeyknoxEntry {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*KeyknoxEntry).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewKeyknoxEntryWithCtx(pointer unsafe.Pointer) *KeyknoxEntry {
    ctx := (*C.vssk_keyknox_entry_t /*ct2*/)(pointer)
    obj := &KeyknoxEntry {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*KeyknoxEntry).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewKeyknoxEntryCopy(pointer unsafe.Pointer) *KeyknoxEntry {
    ctx := (*C.vssk_keyknox_entry_t /*ct2*/)(pointer)
    obj := &KeyknoxEntry {
        cCtx: C.vssk_keyknox_entry_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*KeyknoxEntry).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *KeyknoxEntry) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *KeyknoxEntry) delete() {
    C.vssk_keyknox_entry_delete(obj.cCtx)
}

/*
* Create Keyknox entry without "owner".
* Suitable for the push operation to the the Keyknox Service.
*/
func NewKeyknoxEntryWith(root string, path string, key string, identities *sdk_core.StringList, meta []byte, value []byte, hash []byte) *KeyknoxEntry {
    rootChar := C.CString(root)
    defer C.free(unsafe.Pointer(rootChar))
    rootStr := C.vsc_str_from_str(rootChar)
    pathChar := C.CString(path)
    defer C.free(unsafe.Pointer(pathChar))
    pathStr := C.vsc_str_from_str(pathChar)
    keyChar := C.CString(key)
    defer C.free(unsafe.Pointer(keyChar))
    keyStr := C.vsc_str_from_str(keyChar)
    metaData := helperWrapData (meta)
    valueData := helperWrapData (value)
    hashData := helperWrapData (hash)

    proxyResult := /*pr4*/C.vssk_keyknox_entry_new_with(rootStr, pathStr, keyStr, (*C.vssc_string_list_t)(unsafe.Pointer(identities.Ctx())), metaData, valueData, hashData)

    runtime.KeepAlive(root)

    runtime.KeepAlive(path)

    runtime.KeepAlive(key)

    runtime.KeepAlive(identities)

    obj := &KeyknoxEntry {
        cCtx: proxyResult,
    }
    runtime.SetFinalizer(obj, (*KeyknoxEntry).Delete)
    return obj
}

/*
* Create fully defined Keyknox entry.
*/
func NewKeyknoxEntryWithOwner(owner string, root string, path string, key string, identities *sdk_core.StringList, meta []byte, value []byte, hash []byte) *KeyknoxEntry {
    ownerChar := C.CString(owner)
    defer C.free(unsafe.Pointer(ownerChar))
    ownerStr := C.vsc_str_from_str(ownerChar)
    rootChar := C.CString(root)
    defer C.free(unsafe.Pointer(rootChar))
    rootStr := C.vsc_str_from_str(rootChar)
    pathChar := C.CString(path)
    defer C.free(unsafe.Pointer(pathChar))
    pathStr := C.vsc_str_from_str(pathChar)
    keyChar := C.CString(key)
    defer C.free(unsafe.Pointer(keyChar))
    keyStr := C.vsc_str_from_str(keyChar)
    metaData := helperWrapData (meta)
    valueData := helperWrapData (value)
    hashData := helperWrapData (hash)

    proxyResult := /*pr4*/C.vssk_keyknox_entry_new_with_owner(ownerStr, rootStr, pathStr, keyStr, (*C.vssc_string_list_t)(unsafe.Pointer(identities.Ctx())), metaData, valueData, hashData)

    runtime.KeepAlive(owner)

    runtime.KeepAlive(root)

    runtime.KeepAlive(path)

    runtime.KeepAlive(key)

    runtime.KeepAlive(identities)

    obj := &KeyknoxEntry {
        cCtx: proxyResult,
    }
    runtime.SetFinalizer(obj, (*KeyknoxEntry).Delete)
    return obj
}

/*
* Create Keyknox entry that was reset.
*/
func NewKeyknoxEntryWithResetEntry(owner string, root string, path string, key string) *KeyknoxEntry {
    ownerChar := C.CString(owner)
    defer C.free(unsafe.Pointer(ownerChar))
    ownerStr := C.vsc_str_from_str(ownerChar)
    rootChar := C.CString(root)
    defer C.free(unsafe.Pointer(rootChar))
    rootStr := C.vsc_str_from_str(rootChar)
    pathChar := C.CString(path)
    defer C.free(unsafe.Pointer(pathChar))
    pathStr := C.vsc_str_from_str(pathChar)
    keyChar := C.CString(key)
    defer C.free(unsafe.Pointer(keyChar))
    keyStr := C.vsc_str_from_str(keyChar)

    proxyResult := /*pr4*/C.vssk_keyknox_entry_new_with_reset_entry(ownerStr, rootStr, pathStr, keyStr)

    runtime.KeepAlive(owner)

    runtime.KeepAlive(root)

    runtime.KeepAlive(path)

    runtime.KeepAlive(key)

    obj := &KeyknoxEntry {
        cCtx: proxyResult,
    }
    runtime.SetFinalizer(obj, (*KeyknoxEntry).Delete)
    return obj
}

/*
* Return owner.
*/
func (obj *KeyknoxEntry) Owner() string {
    proxyResult := /*pr4*/C.vssk_keyknox_entry_owner(obj.cCtx)

    runtime.KeepAlive(obj)

    return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */
}

/*
* Return root path.
*/
func (obj *KeyknoxEntry) Root() string {
    proxyResult := /*pr4*/C.vssk_keyknox_entry_root(obj.cCtx)

    runtime.KeepAlive(obj)

    return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */
}

/*
* Return second path.
*/
func (obj *KeyknoxEntry) Path() string {
    proxyResult := /*pr4*/C.vssk_keyknox_entry_path(obj.cCtx)

    runtime.KeepAlive(obj)

    return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */
}

/*
* Return key.
*/
func (obj *KeyknoxEntry) Key() string {
    proxyResult := /*pr4*/C.vssk_keyknox_entry_key(obj.cCtx)

    runtime.KeepAlive(obj)

    return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */
}

/*
* Return list of users that have access to the entry.
*/
func (obj *KeyknoxEntry) Identities() *sdk_core.StringList {
    proxyResult := /*pr4*/C.vssk_keyknox_entry_identities(obj.cCtx)

    runtime.KeepAlive(obj)

    return sdk_core.NewStringListCopy(unsafe.Pointer(proxyResult)) /* r5 */
}

/*
* Return meta.
*/
func (obj *KeyknoxEntry) Meta() []byte {
    proxyResult := /*pr4*/C.vssk_keyknox_entry_meta(obj.cCtx)

    runtime.KeepAlive(obj)

    return helperExtractData(proxyResult) /* r1 */
}

/*
* Return value.
*/
func (obj *KeyknoxEntry) Value() []byte {
    proxyResult := /*pr4*/C.vssk_keyknox_entry_value(obj.cCtx)

    runtime.KeepAlive(obj)

    return helperExtractData(proxyResult) /* r1 */
}

/*
* Return hash.
*/
func (obj *KeyknoxEntry) Hash() []byte {
    proxyResult := /*pr4*/C.vssk_keyknox_entry_hash(obj.cCtx)

    runtime.KeepAlive(obj)

    return helperExtractData(proxyResult) /* r1 */
}
