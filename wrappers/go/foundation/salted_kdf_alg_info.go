package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_common
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_foundation
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import . "virgil/common"

/*
* Handle KDF algorithms that are configured with salt and iteration count.
*/
type SaltedKdfAlgInfo struct {
    IAlgInfo
    ctx *C.vscf_impl_t
}

/*
* Return hash algorithm information.
*/
func (this SaltedKdfAlgInfo) HashAlgInfo () IAlgInfo {
    proxyResult := C.vscf_salted_kdf_alg_info_hash_alg_info(this.ctx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Return KDF salt.
*/
func (this SaltedKdfAlgInfo) Salt () []byte {
    proxyResult := C.vscf_salted_kdf_alg_info_salt(this.ctx)

    return ExtractData(proxyResult) /* r1 */
}

/*
* Return KDF iteration count.
* Note, can be 0 if KDF does not need the iteration count.
*/
func (this SaltedKdfAlgInfo) IterationCount () int32 {
    proxyResult := C.vscf_salted_kdf_alg_info_iteration_count(this.ctx)

    return proxyResult //r9
}

/* Handle underlying C context. */
func (this SaltedKdfAlgInfo) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewSaltedKdfAlgInfo () *SaltedKdfAlgInfo {
    ctx := C.vscf_salted_kdf_alg_info_new()
    return &SaltedKdfAlgInfo {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewSaltedKdfAlgInfoWithCtx (ctx *C.vscf_impl_t) *SaltedKdfAlgInfo {
    return &SaltedKdfAlgInfo {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewSaltedKdfAlgInfoCopy (ctx *C.vscf_impl_t) *SaltedKdfAlgInfo {
    return &SaltedKdfAlgInfo {
        ctx: C.vscf_salted_kdf_alg_info_shallow_copy(ctx),
    }
}

/*
* Create algorithm info with identificator, HASH algorithm info,
* salt and iteration count.
*/
func NewSaltedKdfAlgInfowithMembers (algId AlgId, hashAlgInfo IAlgInfo, salt []byte, iterationCount int32) *SaltedKdfAlgInfo {
    hashAlgInfoCopy := C.vscf_impl_shallow_copy(hashAlgInfo.Ctx())

    proxyResult := C.vscf_salted_kdf_alg_info_new_with_members(algId /*pa7*/, &hashAlgInfoCopy, WrapData(salt), iterationCount)

    return &SaltedKdfAlgInfo {
        ctx: proxyResult,
    }
}

/*
* Provide algorithm identificator.
*/
func (this SaltedKdfAlgInfo) AlgId () AlgId {
    proxyResult := C.vscf_salted_kdf_alg_info_alg_id(this.ctx)

    return AlgId(proxyResult) /* r8 */
}
