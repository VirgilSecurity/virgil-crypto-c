package sdk_core

// #include <virgil/sdk/core/vssc_core_sdk_public.h>
import "C"
import unsafe "unsafe"
import "runtime"
import foundation "virgil/foundation"

/*
* Class responsible for JWT generation.
 */
type JwtGenerator struct {
	cCtx *C.vssc_jwt_generator_t /*ct2*/
}

const (
	JwtGeneratorDefaultTtl uint = 15 * 60
)

/* Handle underlying C context. */
func (obj *JwtGenerator) Ctx() uintptr {
	return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewJwtGenerator() *JwtGenerator {
	ctx := C.vssc_jwt_generator_new()
	obj := &JwtGenerator{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*JwtGenerator).Delete)
	return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewJwtGeneratorWithCtx(pointer unsafe.Pointer) *JwtGenerator {
	ctx := (*C.vssc_jwt_generator_t /*ct2*/)(pointer)
	obj := &JwtGenerator{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*JwtGenerator).Delete)
	return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewJwtGeneratorCopy(pointer unsafe.Pointer) *JwtGenerator {
	ctx := (*C.vssc_jwt_generator_t /*ct2*/)(pointer)
	obj := &JwtGenerator{
		cCtx: C.vssc_jwt_generator_shallow_copy(ctx),
	}
	runtime.SetFinalizer(obj, (*JwtGenerator).Delete)
	return obj
}

/*
* Release underlying C context.
 */
func (obj *JwtGenerator) Delete() {
	if obj == nil {
		return
	}
	runtime.SetFinalizer(obj, nil)
	obj.delete()
}

/*
* Release underlying C context.
 */
func (obj *JwtGenerator) delete() {
	C.vssc_jwt_generator_delete(obj.cCtx)
}

/*
* Create JWT generator with an application credentials.
 */
func NewJwtGeneratorWithCredentials(appId string, appKeyId string, appKey foundation.PrivateKey) *JwtGenerator {
	appIdChar := C.CString(appId)
	defer C.free(unsafe.Pointer(appIdChar))
	appIdStr := C.vsc_str_from_str(appIdChar)
	appKeyIdChar := C.CString(appKeyId)
	defer C.free(unsafe.Pointer(appKeyIdChar))
	appKeyIdStr := C.vsc_str_from_str(appKeyIdChar)

	proxyResult := /*pr4*/ C.vssc_jwt_generator_new_with_credentials(appIdStr, appKeyIdStr, (*C.vscf_impl_t)(unsafe.Pointer(appKey.Ctx())))

	runtime.KeepAlive(appId)

	runtime.KeepAlive(appKeyId)

	runtime.KeepAlive(appKey)

	obj := &JwtGenerator{
		cCtx: proxyResult,
	}
	runtime.SetFinalizer(obj, (*JwtGenerator).Delete)
	return obj
}

func (obj *JwtGenerator) SetRandom(random foundation.Random) {
	C.vssc_jwt_generator_release_random(obj.cCtx)
	C.vssc_jwt_generator_use_random(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(random.Ctx())))

	runtime.KeepAlive(random)
	runtime.KeepAlive(obj)
}

/*
* Setup predefined values to the uninitialized class dependencies.
 */
func (obj *JwtGenerator) SetupDefaults() error {
	proxyResult := /*pr4*/ C.vssc_jwt_generator_setup_defaults(obj.cCtx)

	err := CoreSdkErrorHandleStatus(proxyResult)
	if err != nil {
		return err
	}

	runtime.KeepAlive(obj)

	return nil
}

/*
* Set JWT TTL.
 */
func (obj *JwtGenerator) SetTtl(ttl uint) {
	C.vssc_jwt_generator_set_ttl(obj.cCtx, (C.size_t)(ttl) /*pa10*/)

	runtime.KeepAlive(obj)

	return
}

/*
* Generate new JWT.
 */
func (obj *JwtGenerator) GenerateToken(identity string) (*Jwt, error) {
	var error C.vssc_error_t
	C.vssc_error_reset(&error)
	identityChar := C.CString(identity)
	defer C.free(unsafe.Pointer(identityChar))
	identityStr := C.vsc_str_from_str(identityChar)

	proxyResult := /*pr4*/ C.vssc_jwt_generator_generate_token(obj.cCtx, identityStr, &error)

	err := CoreSdkErrorHandleStatus(error.status)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(identity)

	return NewJwtWithCtx(unsafe.Pointer(proxyResult)) /* r6 */, nil
}
