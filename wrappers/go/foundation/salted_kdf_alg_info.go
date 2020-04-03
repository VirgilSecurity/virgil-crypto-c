package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import "runtime"
import unsafe "unsafe"


/*
* Handle KDF algorithms that are configured with salt and iteration count.
*/
type SaltedKdfAlgInfo struct {
    cCtx *C.vscf_salted_kdf_alg_info_t /*ct10*/
}

/*
* Return hash algorithm information.
*/
func (obj *SaltedKdfAlgInfo) HashAlgInfo() (AlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_salted_kdf_alg_info_hash_alg_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapAlgInfoCopy(proxyResult) /* r4 */
}

/*
* Return KDF salt.
*/
func (obj *SaltedKdfAlgInfo) Salt() []byte {
    proxyResult := /*pr4*/C.vscf_salted_kdf_alg_info_salt(obj.cCtx)

    runtime.KeepAlive(obj)

    return helperExtractData(proxyResult) /* r1 */
}

/*
* Return KDF iteration count.
* Note, can be 0 if KDF does not need the iteration count.
*/
func (obj *SaltedKdfAlgInfo) IterationCount() uint {
    proxyResult := /*pr4*/C.vscf_salted_kdf_alg_info_iteration_count(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/* Handle underlying C context. */
func (obj *SaltedKdfAlgInfo) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewSaltedKdfAlgInfo() *SaltedKdfAlgInfo {
    ctx := C.vscf_salted_kdf_alg_info_new()
    obj := &SaltedKdfAlgInfo {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*SaltedKdfAlgInfo).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newSaltedKdfAlgInfoWithCtx(ctx *C.vscf_salted_kdf_alg_info_t /*ct10*/) *SaltedKdfAlgInfo {
    obj := &SaltedKdfAlgInfo {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*SaltedKdfAlgInfo).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newSaltedKdfAlgInfoCopy(ctx *C.vscf_salted_kdf_alg_info_t /*ct10*/) *SaltedKdfAlgInfo {
    obj := &SaltedKdfAlgInfo {
        cCtx: C.vscf_salted_kdf_alg_info_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*SaltedKdfAlgInfo).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *SaltedKdfAlgInfo) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *SaltedKdfAlgInfo) delete() {
    C.vscf_salted_kdf_alg_info_delete(obj.cCtx)
}

/*
* Provide algorithm identificator.
*/
func (obj *SaltedKdfAlgInfo) AlgId() AlgId {
    proxyResult := /*pr4*/C.vscf_salted_kdf_alg_info_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult) /* r8 */
}
