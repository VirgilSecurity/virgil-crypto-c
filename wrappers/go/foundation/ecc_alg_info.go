package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"

/*
* Handle algorithm information about ECP.
*/
type EccAlgInfo struct {
    IAlgInfo
    cCtx *C.vscf_ecc_alg_info_t /*ct10*/
}

/*
* Return EC specific algorithm identificator {unrestricted, ecDH, ecMQV}.
*/
func (this EccAlgInfo) KeyId () OidId {
    proxyResult := /*pr4*/C.vscf_ecc_alg_info_key_id(this.cCtx)

    return OidId(proxyResult) /* r8 */
}

/*
* Return EC domain group identificator.
*/
func (this EccAlgInfo) DomainId () OidId {
    proxyResult := /*pr4*/C.vscf_ecc_alg_info_domain_id(this.cCtx)

    return OidId(proxyResult) /* r8 */
}

/* Handle underlying C context. */
func (this EccAlgInfo) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(this.cCtx)
}

func NewEccAlgInfo () *EccAlgInfo {
    ctx := C.vscf_ecc_alg_info_new()
    return &EccAlgInfo {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newEccAlgInfoWithCtx (ctx *C.vscf_ecc_alg_info_t /*ct10*/) *EccAlgInfo {
    return &EccAlgInfo {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newEccAlgInfoCopy (ctx *C.vscf_ecc_alg_info_t /*ct10*/) *EccAlgInfo {
    return &EccAlgInfo {
        cCtx: C.vscf_ecc_alg_info_shallow_copy(ctx),
    }
}

/// Release underlying C context.
func (this EccAlgInfo) close () {
    C.vscf_ecc_alg_info_delete(this.cCtx)
}

/*
* Create algorithm info with EC generic key identificator, EC domain group identificator.
*/
func NewEccAlgInfoWithMembers (algId AlgId, keyId OidId, domainId OidId) *EccAlgInfo {
    proxyResult := /*pr4*/C.vscf_ecc_alg_info_new_with_members(C.vscf_alg_id_t(algId) /*pa7*/, C.vscf_oid_id_t(keyId) /*pa7*/, C.vscf_oid_id_t(domainId) /*pa7*/)

    return &EccAlgInfo {
        cCtx: proxyResult,
    }
}

/*
* Provide algorithm identificator.
*/
func (this EccAlgInfo) AlgId () AlgId {
    proxyResult := /*pr4*/C.vscf_ecc_alg_info_alg_id(this.cCtx)

    return AlgId(proxyResult) /* r8 */
}
