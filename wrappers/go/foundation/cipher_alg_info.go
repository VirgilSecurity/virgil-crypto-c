package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"


/*
* Handle symmetric cipher algorithm information.
*/
type CipherAlgInfo struct {
    IAlgInfo
    cCtx *C.vscf_cipher_alg_info_t /*ct10*/
}

/*
* Return IV.
*/
func (obj *CipherAlgInfo) Nonce () []byte {
    proxyResult := /*pr4*/C.vscf_cipher_alg_info_nonce(obj.cCtx)

    return helperExtractData(proxyResult) /* r1 */
}

/* Handle underlying C context. */
func (obj *CipherAlgInfo) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(obj.cCtx)
}

func NewCipherAlgInfo () *CipherAlgInfo {
    ctx := C.vscf_cipher_alg_info_new()
    return &CipherAlgInfo {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newCipherAlgInfoWithCtx (ctx *C.vscf_cipher_alg_info_t /*ct10*/) *CipherAlgInfo {
    return &CipherAlgInfo {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newCipherAlgInfoCopy (ctx *C.vscf_cipher_alg_info_t /*ct10*/) *CipherAlgInfo {
    return &CipherAlgInfo {
        cCtx: C.vscf_cipher_alg_info_shallow_copy(ctx),
    }
}

/*
* Release underlying C context.
*/
func (obj *CipherAlgInfo) Delete () {
    C.vscf_cipher_alg_info_delete(obj.cCtx)
}

/*
* Create symmetric cipher algorithm info with identificator and input vector.
*/
func NewCipherAlgInfoWithMembers (algId AlgId, nonce []byte) *CipherAlgInfo {
    nonceData := helperWrapData (nonce)

    proxyResult := /*pr4*/C.vscf_cipher_alg_info_new_with_members(C.vscf_alg_id_t(algId) /*pa7*/, nonceData)

    return &CipherAlgInfo {
        cCtx: proxyResult,
    }
}

/*
* Provide algorithm identificator.
*/
func (obj *CipherAlgInfo) AlgId () AlgId {
    proxyResult := /*pr4*/C.vscf_cipher_alg_info_alg_id(obj.cCtx)

    return AlgId(proxyResult) /* r8 */
}
