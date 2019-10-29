package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"

/*
* Handle information about password-based encryption algorithm.
*/
type PbeAlgInfo struct {
    IAlgInfo
    cCtx *C.vscf_pbe_alg_info_t /*ct10*/
}

/*
* Return KDF algorithm information.
*/
func (this PbeAlgInfo) KdfAlgInfo () (IAlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_pbe_alg_info_kdf_alg_info(this.cCtx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Return cipher algorithm information.
*/
func (this PbeAlgInfo) CipherAlgInfo () (IAlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_pbe_alg_info_cipher_alg_info(this.cCtx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/* Handle underlying C context. */
func (this PbeAlgInfo) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(this.cCtx)
}

func NewPbeAlgInfo () *PbeAlgInfo {
    ctx := C.vscf_pbe_alg_info_new()
    return &PbeAlgInfo {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newPbeAlgInfoWithCtx (ctx *C.vscf_pbe_alg_info_t /*ct10*/) *PbeAlgInfo {
    return &PbeAlgInfo {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newPbeAlgInfoCopy (ctx *C.vscf_pbe_alg_info_t /*ct10*/) *PbeAlgInfo {
    return &PbeAlgInfo {
        cCtx: C.vscf_pbe_alg_info_shallow_copy(ctx),
    }
}

/// Release underlying C context.
func (this PbeAlgInfo) close () {
    C.vscf_pbe_alg_info_delete(this.cCtx)
}

/*
* Create algorithm info with identificator, KDF algorithm info and
* cipher alg info.
*/
func NewPbeAlgInfoWithMembers (algId AlgId, kdfAlgInfo IAlgInfo, cipherAlgInfo IAlgInfo) *PbeAlgInfo {
    kdfAlgInfoCopy := C.vscf_impl_shallow_copy((*C.vscf_impl_t)(kdfAlgInfo.ctx()))
    cipherAlgInfoCopy := C.vscf_impl_shallow_copy((*C.vscf_impl_t)(cipherAlgInfo.ctx()))

    proxyResult := /*pr4*/C.vscf_pbe_alg_info_new_with_members(C.vscf_alg_id_t(algId) /*pa7*/, &kdfAlgInfoCopy, &cipherAlgInfoCopy)

    return &PbeAlgInfo {
        cCtx: proxyResult,
    }
}

/*
* Provide algorithm identificator.
*/
func (this PbeAlgInfo) AlgId () AlgId {
    proxyResult := /*pr4*/C.vscf_pbe_alg_info_alg_id(this.cCtx)

    return AlgId(proxyResult) /* r8 */
}
