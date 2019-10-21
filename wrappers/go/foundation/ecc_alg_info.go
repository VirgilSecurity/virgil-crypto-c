package foundation

// #cgo CFLAGS: -I${SRCDIR}/../../../build/library/foundation/include/virgil/crypto/foundation
// #cgo CFLAGS: -I${SRCDIR}/../../../library/foundation/include/virgil/crypto/foundation
// #cgo LDFLAGS: -L${SRCDIR}/../../java/binaries/linux/lib -lvscf_foundation_java
// #include <vscf_foundation_public.h>
import "C"

/*
* Handle algorithm information about ECP.
*/
type EccAlgInfo struct {
    IAlgInfo
    ctx *C.vscf_impl_t
}

/*
* Return EC specific algorithm identificator {unrestricted, ecDH, ecMQV}.
*/
func (this EccAlgInfo) KeyId () OidId {
    proxyResult := C.vscf_ecc_alg_info_key_id(this.ctx)

    return OidId(proxyResult) /* r8 */
}

/*
* Return EC domain group identificator.
*/
func (this EccAlgInfo) DomainId () OidId {
    proxyResult := C.vscf_ecc_alg_info_domain_id(this.ctx)

    return OidId(proxyResult) /* r8 */
}

/* Handle underlying C context. */
func (this EccAlgInfo) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewEccAlgInfo () *EccAlgInfo {
    ctx := C.vscf_ecc_alg_info_new()
    return &EccAlgInfo {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewEccAlgInfoWithCtx (ctx *C.vscf_impl_t) *EccAlgInfo {
    return &EccAlgInfo {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewEccAlgInfoCopy (ctx *C.vscf_impl_t) *EccAlgInfo {
    return &EccAlgInfo {
        ctx: C.vscf_ecc_alg_info_shallow_copy(ctx),
    }
}

/*
* Create algorithm info with EC generic key identificator, EC domain group identificator.
*/
func NewEccAlgInfowithMembers (algId AlgId, keyId OidId, domainId OidId) *EccAlgInfo {
    proxyResult := C.vscf_ecc_alg_info_new_with_members(algId /*pa7*/, keyId /*pa7*/, domainId /*pa7*/)

    return &EccAlgInfo {
        ctx: proxyResult,
    }
}

/*
* Provide algorithm identificator.
*/
func (this EccAlgInfo) AlgId () AlgId {
    proxyResult := C.vscf_ecc_alg_info_alg_id(this.ctx)

    return AlgId(proxyResult) /* r8 */
}
