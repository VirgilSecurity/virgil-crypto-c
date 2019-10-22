package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_common
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_foundation
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"

/*
* Handle hashed based algorithm information, i.e. HKDF, HMAC, etc.
*/
type HashBasedAlgInfo struct {
    IAlgInfo
    ctx *C.vscf_impl_t
}

/*
* Return hash algorithm information.
*/
func (this HashBasedAlgInfo) HashAlgInfo () IAlgInfo {
    proxyResult := C.vscf_hash_based_alg_info_hash_alg_info(this.ctx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/* Handle underlying C context. */
func (this HashBasedAlgInfo) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewHashBasedAlgInfo () *HashBasedAlgInfo {
    ctx := C.vscf_hash_based_alg_info_new()
    return &HashBasedAlgInfo {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewHashBasedAlgInfoWithCtx (ctx *C.vscf_impl_t) *HashBasedAlgInfo {
    return &HashBasedAlgInfo {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewHashBasedAlgInfoCopy (ctx *C.vscf_impl_t) *HashBasedAlgInfo {
    return &HashBasedAlgInfo {
        ctx: C.vscf_hash_based_alg_info_shallow_copy(ctx),
    }
}

/*
* Create algorithm info with identificator and HASH algorithm info.
*/
func NewHashBasedAlgInfowithMembers (algId AlgId, hashAlgInfo IAlgInfo) *HashBasedAlgInfo {
    hashAlgInfoCopy := C.vscf_impl_shallow_copy(hashAlgInfo.Ctx())

    proxyResult := C.vscf_hash_based_alg_info_new_with_members(algId /*pa7*/, &hashAlgInfoCopy)

    return &HashBasedAlgInfo {
        ctx: proxyResult,
    }
}

/*
* Provide algorithm identificator.
*/
func (this HashBasedAlgInfo) AlgId () AlgId {
    proxyResult := C.vscf_hash_based_alg_info_alg_id(this.ctx)

    return AlgId(proxyResult) /* r8 */
}
