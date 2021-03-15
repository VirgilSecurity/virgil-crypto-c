package sdk_core

// #include <virgil/sdk/core/vssc_core_sdk_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Class that handles JWT.
*/
type Jwt struct {
    cCtx *C.vssc_jwt_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *Jwt) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewJwt() *Jwt {
    ctx := C.vssc_jwt_new()
    obj := &Jwt {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*Jwt).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newJwtWithCtx(ctx *C.vssc_jwt_t /*ct2*/) *Jwt {
    obj := &Jwt {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*Jwt).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newJwtCopy(ctx *C.vssc_jwt_t /*ct2*/) *Jwt {
    obj := &Jwt {
        cCtx: C.vssc_jwt_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*Jwt).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *Jwt) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *Jwt) delete() {
    C.vssc_jwt_delete(obj.cCtx)
}

/*
* Parse JWT from a string representation.
*/
func JwtParse(str string) (*Jwt, error) {
    var error C.vssc_error_t
    C.vssc_error_reset(&error)
    strChar := C.CString(str)
    defer C.free(unsafe.Pointer(strChar))
    strStr := C.vsc_str_from_str(strChar)

    proxyResult := /*pr4*/C.vssc_jwt_parse(strStr, &error)

    err := CoreSdkErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(str)

    return newJwtWithCtx(proxyResult) /* r6 */, nil
}

/*
* Return JWT string representation.
*/
func (obj *Jwt) AsString() string {
    proxyResult := /*pr4*/C.vssc_jwt_as_string(obj.cCtx)

    runtime.KeepAlive(obj)

    return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */
}

/*
* Return identity to whom this token was issued.
*/
func (obj *Jwt) Identity() string {
    proxyResult := /*pr4*/C.vssc_jwt_identity(obj.cCtx)

    runtime.KeepAlive(obj)

    return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */
}

/*
* Return true if token is expired.
*/
func (obj *Jwt) IsExpired() bool {
    proxyResult := /*pr4*/C.vssc_jwt_is_expired(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}
