package sdk_comm_kit

// #include <virgil/sdk/comm-kit/vssq_comm_kit_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Handles access info to a specific CloudFS entry.
*/
type MessengerCloudFsAccess struct {
    cCtx *C.vssq_messenger_cloud_fs_access_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *MessengerCloudFsAccess) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewMessengerCloudFsAccess() *MessengerCloudFsAccess {
    ctx := C.vssq_messenger_cloud_fs_access_new()
    obj := &MessengerCloudFsAccess {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*MessengerCloudFsAccess).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewMessengerCloudFsAccessWithCtx(pointer unsafe.Pointer) *MessengerCloudFsAccess {
    ctx := (*C.vssq_messenger_cloud_fs_access_t /*ct2*/)(pointer)
    obj := &MessengerCloudFsAccess {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*MessengerCloudFsAccess).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewMessengerCloudFsAccessCopy(pointer unsafe.Pointer) *MessengerCloudFsAccess {
    ctx := (*C.vssq_messenger_cloud_fs_access_t /*ct2*/)(pointer)
    obj := &MessengerCloudFsAccess {
        cCtx: C.vssq_messenger_cloud_fs_access_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*MessengerCloudFsAccess).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *MessengerCloudFsAccess) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *MessengerCloudFsAccess) delete() {
    C.vssq_messenger_cloud_fs_access_delete(obj.cCtx)
}

/*
* Create an object with required fields.
*/
func NewMessengerCloudFsAccessWithIdentity(identity string, permission MessengerCloudFsPermission) *MessengerCloudFsAccess {
    identityChar := C.CString(identity)
    defer C.free(unsafe.Pointer(identityChar))
    identityStr := C.vsc_str_from_str(identityChar)

    proxyResult := /*pr4*/C.vssq_messenger_cloud_fs_access_new_with_identity(identityStr, C.vssq_messenger_cloud_fs_permission_t(permission) /*pa7*/)

    runtime.KeepAlive(identity)

    obj := &MessengerCloudFsAccess {
        cCtx: proxyResult,
    }
    runtime.SetFinalizer(obj, (*MessengerCloudFsAccess).Delete)
    return obj
}

/*
* Create an object with required fields.
*/
func NewMessengerCloudFsAccessWithUser(user *MessengerUser, permission MessengerCloudFsPermission) *MessengerCloudFsAccess {
    proxyResult := /*pr4*/C.vssq_messenger_cloud_fs_access_new_with_user((*C.vssq_messenger_user_t)(unsafe.Pointer(user.Ctx())), C.vssq_messenger_cloud_fs_permission_t(permission) /*pa7*/)

    runtime.KeepAlive(user)

    obj := &MessengerCloudFsAccess {
        cCtx: proxyResult,
    }
    runtime.SetFinalizer(obj, (*MessengerCloudFsAccess).Delete)
    return obj
}

/*
* Return true if user that has access to a CloudFS entry was defined.
*/
func (obj *MessengerCloudFsAccess) HasUser() bool {
    proxyResult := /*pr4*/C.vssq_messenger_cloud_fs_access_has_user(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Return a user that has access to a CloudFS entry.
*/
func (obj *MessengerCloudFsAccess) User() *MessengerUser {
    proxyResult := /*pr4*/C.vssq_messenger_cloud_fs_access_user(obj.cCtx)

    runtime.KeepAlive(obj)

    return NewMessengerUserCopy(unsafe.Pointer(proxyResult)) /* r5 */
}

/*
* Return a user's identity.
*/
func (obj *MessengerCloudFsAccess) Identity() string {
    proxyResult := /*pr4*/C.vssq_messenger_cloud_fs_access_identity(obj.cCtx)

    runtime.KeepAlive(obj)

    return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */
}

/*
* Return a user's permission to a CloudFS entry.
*/
func (obj *MessengerCloudFsAccess) Permission() MessengerCloudFsPermission {
    proxyResult := /*pr4*/C.vssq_messenger_cloud_fs_access_permission(obj.cCtx)

    runtime.KeepAlive(obj)

    return MessengerCloudFsPermission(proxyResult) /* r8 */
}
