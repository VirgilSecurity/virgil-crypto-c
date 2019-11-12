package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_foundation -lvsc_foundation_pb -led25519 -lprotobuf-nanopb -lvsc_common -lmbedcrypto
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"


/*
* Handle hashed based algorithm information, i.e. HKDF, HMAC, etc.
*/
type HashBasedAlgInfo struct {
    IAlgInfo
    cCtx *C.vscf_hash_based_alg_info_t /*ct10*/
}

/*
* Return hash algorithm information.
*/
func (obj *HashBasedAlgInfo) HashAlgInfo () (IAlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_hash_based_alg_info_hash_alg_info(obj.cCtx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/* Handle underlying C context. */
func (obj *HashBasedAlgInfo) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(obj.cCtx)
}

func NewHashBasedAlgInfo () *HashBasedAlgInfo {
    ctx := C.vscf_hash_based_alg_info_new()
    return &HashBasedAlgInfo {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newHashBasedAlgInfoWithCtx (ctx *C.vscf_hash_based_alg_info_t /*ct10*/) *HashBasedAlgInfo {
    return &HashBasedAlgInfo {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newHashBasedAlgInfoCopy (ctx *C.vscf_hash_based_alg_info_t /*ct10*/) *HashBasedAlgInfo {
    return &HashBasedAlgInfo {
        cCtx: C.vscf_hash_based_alg_info_shallow_copy(ctx),
    }
}

/*
* Release underlying C context.
*/
func (obj *HashBasedAlgInfo) Delete () {
    C.vscf_hash_based_alg_info_delete(obj.cCtx)
}

/*
* Create algorithm info with identificator and HASH algorithm info.
*/
func NewHashBasedAlgInfoWithMembers (algId AlgId, hashAlgInfo IAlgInfo) *HashBasedAlgInfo {
    hashAlgInfoCopy := C.vscf_impl_shallow_copy((*C.vscf_impl_t)(hashAlgInfo.ctx()))

    proxyResult := /*pr4*/C.vscf_hash_based_alg_info_new_with_members(C.vscf_alg_id_t(algId) /*pa7*/, &hashAlgInfoCopy)

    return &HashBasedAlgInfo {
        cCtx: proxyResult,
    }
}

/*
* Provide algorithm identificator.
*/
func (obj *HashBasedAlgInfo) AlgId () AlgId {
    proxyResult := /*pr4*/C.vscf_hash_based_alg_info_alg_id(obj.cCtx)

    return AlgId(proxyResult) /* r8 */
}
