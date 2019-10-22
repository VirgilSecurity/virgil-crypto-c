package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_common
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_foundation
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"

/*
* Handle simple algorithm information (just id).
*/
type SimpleAlgInfo struct {
    IAlgInfo
    ctx *C.vscf_impl_t
}

/* Handle underlying C context. */
func (this SimpleAlgInfo) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewSimpleAlgInfo () *SimpleAlgInfo {
    ctx := C.vscf_simple_alg_info_new()
    return &SimpleAlgInfo {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewSimpleAlgInfoWithCtx (ctx *C.vscf_impl_t) *SimpleAlgInfo {
    return &SimpleAlgInfo {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewSimpleAlgInfoCopy (ctx *C.vscf_impl_t) *SimpleAlgInfo {
    return &SimpleAlgInfo {
        ctx: C.vscf_simple_alg_info_shallow_copy(ctx),
    }
}

/*
* Create algorithm info with identificator.
*/
func NewSimpleAlgInfowithAlgId (algId AlgId) *SimpleAlgInfo {
    proxyResult := C.vscf_simple_alg_info_new_with_alg_id(algId /*pa7*/)

    return &SimpleAlgInfo {
        ctx: proxyResult,
    }
}

/*
* Provide algorithm identificator.
*/
func (this SimpleAlgInfo) AlgId () AlgId {
    proxyResult := C.vscf_simple_alg_info_alg_id(this.ctx)

    return AlgId(proxyResult) /* r8 */
}
