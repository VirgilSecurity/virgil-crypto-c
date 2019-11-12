package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_foundation -lvsc_foundation_pb -led25519 -lprotobuf-nanopb -lvsc_common -lmbedcrypto
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"


/*
* Handle simple algorithm information (just id).
*/
type SimpleAlgInfo struct {
    IAlgInfo
    cCtx *C.vscf_simple_alg_info_t /*ct10*/
}

/* Handle underlying C context. */
func (obj *SimpleAlgInfo) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(obj.cCtx)
}

func NewSimpleAlgInfo () *SimpleAlgInfo {
    ctx := C.vscf_simple_alg_info_new()
    return &SimpleAlgInfo {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newSimpleAlgInfoWithCtx (ctx *C.vscf_simple_alg_info_t /*ct10*/) *SimpleAlgInfo {
    return &SimpleAlgInfo {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newSimpleAlgInfoCopy (ctx *C.vscf_simple_alg_info_t /*ct10*/) *SimpleAlgInfo {
    return &SimpleAlgInfo {
        cCtx: C.vscf_simple_alg_info_shallow_copy(ctx),
    }
}

/*
* Release underlying C context.
*/
func (obj *SimpleAlgInfo) Delete () {
    C.vscf_simple_alg_info_delete(obj.cCtx)
}

/*
* Create algorithm info with identificator.
*/
func NewSimpleAlgInfoWithAlgId (algId AlgId) *SimpleAlgInfo {
    proxyResult := /*pr4*/C.vscf_simple_alg_info_new_with_alg_id(C.vscf_alg_id_t(algId) /*pa7*/)

    return &SimpleAlgInfo {
        cCtx: proxyResult,
    }
}

/*
* Provide algorithm identificator.
*/
func (obj *SimpleAlgInfo) AlgId () AlgId {
    proxyResult := /*pr4*/C.vscf_simple_alg_info_alg_id(obj.cCtx)

    return AlgId(proxyResult) /* r8 */
}
