package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_common
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_foundation
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"

/*
* Handle information about password-based encryption algorithm.
*/
type PbeAlgInfo struct {
    IAlgInfo
    ctx *C.vscf_impl_t
}

/*
* Return KDF algorithm information.
*/
func (this PbeAlgInfo) KdfAlgInfo () IAlgInfo {
    proxyResult := C.vscf_pbe_alg_info_kdf_alg_info(this.ctx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Return cipher algorithm information.
*/
func (this PbeAlgInfo) CipherAlgInfo () IAlgInfo {
    proxyResult := C.vscf_pbe_alg_info_cipher_alg_info(this.ctx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/* Handle underlying C context. */
func (this PbeAlgInfo) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewPbeAlgInfo () *PbeAlgInfo {
    ctx := C.vscf_pbe_alg_info_new()
    return &PbeAlgInfo {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewPbeAlgInfoWithCtx (ctx *C.vscf_impl_t) *PbeAlgInfo {
    return &PbeAlgInfo {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewPbeAlgInfoCopy (ctx *C.vscf_impl_t) *PbeAlgInfo {
    return &PbeAlgInfo {
        ctx: C.vscf_pbe_alg_info_shallow_copy(ctx),
    }
}

/*
* Create algorithm info with identificator, KDF algorithm info and
* cipher alg info.
*/
func NewPbeAlgInfowithMembers (algId AlgId, kdfAlgInfo IAlgInfo, cipherAlgInfo IAlgInfo) *PbeAlgInfo {
    kdfAlgInfoCopy := C.vscf_impl_shallow_copy(kdfAlgInfo.Ctx())
    cipherAlgInfoCopy := C.vscf_impl_shallow_copy(cipherAlgInfo.Ctx())

    proxyResult := C.vscf_pbe_alg_info_new_with_members(algId /*pa7*/, &kdfAlgInfoCopy, &cipherAlgInfoCopy)

    return &PbeAlgInfo {
        ctx: proxyResult,
    }
}

/*
* Provide algorithm identificator.
*/
func (this PbeAlgInfo) AlgId () AlgId {
    proxyResult := C.vscf_pbe_alg_info_alg_id(this.ctx)

    return AlgId(proxyResult) /* r8 */
}
