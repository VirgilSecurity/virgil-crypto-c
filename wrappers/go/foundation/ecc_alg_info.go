package foundation

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
func (obj *EccAlgInfo) KeyId () OidId {
    proxyResult := /*pr4*/C.vscf_ecc_alg_info_key_id(obj.cCtx)

    return OidId(proxyResult) /* r8 */
}

/*
* Return EC domain group identificator.
*/
func (obj *EccAlgInfo) DomainId () OidId {
    proxyResult := /*pr4*/C.vscf_ecc_alg_info_domain_id(obj.cCtx)

    return OidId(proxyResult) /* r8 */
}

/* Handle underlying C context. */
func (obj *EccAlgInfo) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(obj.cCtx)
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

/*
* Release underlying C context.
*/
func (obj *EccAlgInfo) Delete () {
    C.vscf_ecc_alg_info_delete(obj.cCtx)
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
func (obj *EccAlgInfo) AlgId () AlgId {
    proxyResult := /*pr4*/C.vscf_ecc_alg_info_alg_id(obj.cCtx)

    return AlgId(proxyResult) /* r8 */
}
