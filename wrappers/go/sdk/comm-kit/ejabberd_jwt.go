package sdk_comm_kit

// #include <virgil/sdk/comm-kit/vssq_comm_kit_public.h>
import "C"
import unsafe "unsafe"
import "runtime"

/*
* Class that handles Ejabberd JWT.
 */
type EjabberdJwt struct {
	cCtx *C.vssq_ejabberd_jwt_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *EjabberdJwt) Ctx() uintptr {
	return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewEjabberdJwt() *EjabberdJwt {
	ctx := C.vssq_ejabberd_jwt_new()
	obj := &EjabberdJwt{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*EjabberdJwt).Delete)
	return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewEjabberdJwtWithCtx(anyctx interface{}) *EjabberdJwt {
	ctx, ok := anyctx.(*C.vssq_ejabberd_jwt_t /*ct2*/)
	if !ok {
		return nil //TODO, &CommKitError{-1,"Cast error for struct EjabberdJwt."}
	}
	obj := &EjabberdJwt{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*EjabberdJwt).Delete)
	return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewEjabberdJwtCopy(anyctx interface{}) *EjabberdJwt {
	ctx, ok := anyctx.(*C.vssq_ejabberd_jwt_t /*ct2*/)
	if !ok {
		return nil //TODO, &CommKitError{-1,"Cast error for struct EjabberdJwt."}
	}
	obj := &EjabberdJwt{
		cCtx: C.vssq_ejabberd_jwt_shallow_copy(ctx),
	}
	runtime.SetFinalizer(obj, (*EjabberdJwt).Delete)
	return obj
}

/*
* Release underlying C context.
 */
func (obj *EjabberdJwt) Delete() {
	if obj == nil {
		return
	}
	runtime.SetFinalizer(obj, nil)
	obj.delete()
}

/*
* Release underlying C context.
 */
func (obj *EjabberdJwt) delete() {
	C.vssq_ejabberd_jwt_delete(obj.cCtx)
}

/*
* Parse Ejabberd JWT from a string representation.
 */
func EjabberdJwtParse(str string) (*EjabberdJwt, error) {
	var error C.vssq_error_t
	C.vssq_error_reset(&error)
	strChar := C.CString(str)
	defer C.free(unsafe.Pointer(strChar))
	strStr := C.vsc_str_from_str(strChar)

	proxyResult := /*pr4*/ C.vssq_ejabberd_jwt_parse(strStr, &error)

	err := CommKitErrorHandleStatus(error.status)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(str)

	return NewEjabberdJwtWithCtx(proxyResult) /* r6 */, nil
}

/*
* Return Ejabberd JWT string representation.
 */
func (obj *EjabberdJwt) AsString() string {
	proxyResult := /*pr4*/ C.vssq_ejabberd_jwt_as_string(obj.cCtx)

	runtime.KeepAlive(obj)

	return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */
}

/*
* Return identity to whom this token was issued.
 */
func (obj *EjabberdJwt) Jid() string {
	proxyResult := /*pr4*/ C.vssq_ejabberd_jwt_jid(obj.cCtx)

	runtime.KeepAlive(obj)

	return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */
}

/*
* Return true if token is expired.
 */
func (obj *EjabberdJwt) IsExpired() bool {
	proxyResult := /*pr4*/ C.vssq_ejabberd_jwt_is_expired(obj.cCtx)

	runtime.KeepAlive(obj)

	return bool(proxyResult) /* r9 */
}
