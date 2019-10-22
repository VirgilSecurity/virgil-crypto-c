package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_common
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_foundation
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import . "virgil/common"

/*
* Handle symmetric cipher algorithm information.
*/
type CipherAlgInfo struct {
    IAlgInfo
    ctx *C.vscf_impl_t
}

/*
* Return IV.
*/
func (this CipherAlgInfo) Nonce () []byte {
    proxyResult := C.vscf_cipher_alg_info_nonce(this.ctx)

    return ExtractData(proxyResult) /* r1 */
}

/* Handle underlying C context. */
func (this CipherAlgInfo) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewCipherAlgInfo () *CipherAlgInfo {
    ctx := C.vscf_cipher_alg_info_new()
    return &CipherAlgInfo {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewCipherAlgInfoWithCtx (ctx *C.vscf_impl_t) *CipherAlgInfo {
    return &CipherAlgInfo {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewCipherAlgInfoCopy (ctx *C.vscf_impl_t) *CipherAlgInfo {
    return &CipherAlgInfo {
        ctx: C.vscf_cipher_alg_info_shallow_copy(ctx),
    }
}

/*
* Create symmetric cipher algorithm info with identificator and input vector.
*/
func NewCipherAlgInfowithMembers (algId AlgId, nonce []byte) *CipherAlgInfo {
    proxyResult := C.vscf_cipher_alg_info_new_with_members(algId /*pa7*/, WrapData(nonce))

    return &CipherAlgInfo {
        ctx: proxyResult,
    }
}

/*
* Provide algorithm identificator.
*/
func (this CipherAlgInfo) AlgId () AlgId {
    proxyResult := C.vscf_cipher_alg_info_alg_id(this.ctx)

    return AlgId(proxyResult) /* r8 */
}
