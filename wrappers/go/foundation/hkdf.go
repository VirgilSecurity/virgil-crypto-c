package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"

/*
* Virgil Security implementation of the HKDF (RFC 6234) algorithm.
 */
type Hkdf struct {
	cCtx *C.vscf_hkdf_t /*ct10*/
}

func (obj *Hkdf) SetHash(hash Hash) {
	C.vscf_hkdf_release_hash(obj.cCtx)
	C.vscf_hkdf_use_hash(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(hash.Ctx())))

	runtime.KeepAlive(hash)
	runtime.KeepAlive(obj)
}

/* Handle underlying C context. */
func (obj *Hkdf) Ctx() uintptr {
	return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewHkdf() *Hkdf {
	ctx := C.vscf_hkdf_new()
	obj := &Hkdf{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*Hkdf).Delete)
	return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewHkdfWithCtx(pointer unsafe.Pointer) *Hkdf {
	ctx := (*C.vscf_hkdf_t /*ct10*/)(pointer)
	obj := &Hkdf{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*Hkdf).Delete)
	return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewHkdfCopy(pointer unsafe.Pointer) *Hkdf {
	ctx := (*C.vscf_hkdf_t /*ct10*/)(pointer)
	obj := &Hkdf{
		cCtx: C.vscf_hkdf_shallow_copy(ctx),
	}
	runtime.SetFinalizer(obj, (*Hkdf).Delete)
	return obj
}

/*
* Release underlying C context.
 */
func (obj *Hkdf) Delete() {
	if obj == nil {
		return
	}
	runtime.SetFinalizer(obj, nil)
	obj.delete()
}

/*
* Release underlying C context.
 */
func (obj *Hkdf) delete() {
	C.vscf_hkdf_delete(obj.cCtx)
}

/*
* Provide algorithm identificator.
 */
func (obj *Hkdf) AlgId() AlgId {
	proxyResult := /*pr4*/ C.vscf_hkdf_alg_id(obj.cCtx)

	runtime.KeepAlive(obj)

	return AlgId(proxyResult) /* r8 */
}

/*
* Produce object with algorithm information and configuration parameters.
 */
func (obj *Hkdf) ProduceAlgInfo() (AlgInfo, error) {
	proxyResult := /*pr4*/ C.vscf_hkdf_produce_alg_info(obj.cCtx)

	runtime.KeepAlive(obj)

	return ImplementationWrapAlgInfo(proxyResult) /* r4 */
}

/*
* Restore algorithm configuration from the given object.
 */
func (obj *Hkdf) RestoreAlgInfo(algInfo AlgInfo) error {
	proxyResult := /*pr4*/ C.vscf_hkdf_restore_alg_info(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(algInfo.Ctx())))

	err := FoundationErrorHandleStatus(proxyResult)
	if err != nil {
		return err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(algInfo)

	return nil
}

/*
* Derive key of the requested length from the given data.
 */
func (obj *Hkdf) Derive(data []byte, keyLen uint) []byte {
	keyBuf, keyBufErr := newBuffer(int(keyLen))
	if keyBufErr != nil {
		return nil
	}
	defer keyBuf.delete()
	dataData := helperWrapData(data)

	C.vscf_hkdf_derive(obj.cCtx, dataData, (C.size_t)(keyLen) /*pa10*/, keyBuf.ctx)

	runtime.KeepAlive(obj)

	return keyBuf.getData() /* r7 */
}

/*
* Prepare algorithm to derive new key.
 */
func (obj *Hkdf) Reset(salt []byte, iterationCount uint) {
	saltData := helperWrapData(salt)

	C.vscf_hkdf_reset(obj.cCtx, saltData, (C.size_t)(iterationCount) /*pa10*/)

	runtime.KeepAlive(obj)

	return
}

/*
* Setup application specific information (optional).
* Can be empty.
 */
func (obj *Hkdf) SetInfo(info []byte) {
	infoData := helperWrapData(info)

	C.vscf_hkdf_set_info(obj.cCtx, infoData)

	runtime.KeepAlive(obj)

	return
}
