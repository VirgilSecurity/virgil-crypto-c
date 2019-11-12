package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_foundation -lvsc_foundation_pb -led25519 -lprotobuf-nanopb -lvsc_common -lmbedcrypto
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"


/*
* Handle KDF algorithms that are configured with salt and iteration count.
*/
type SaltedKdfAlgInfo struct {
    IAlgInfo
    cCtx *C.vscf_salted_kdf_alg_info_t /*ct10*/
}

/*
* Return hash algorithm information.
*/
func (obj *SaltedKdfAlgInfo) HashAlgInfo () (IAlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_salted_kdf_alg_info_hash_alg_info(obj.cCtx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Return KDF salt.
*/
func (obj *SaltedKdfAlgInfo) Salt () []byte {
    proxyResult := /*pr4*/C.vscf_salted_kdf_alg_info_salt(obj.cCtx)

    return helperExtractData(proxyResult) /* r1 */
}

/*
* Return KDF iteration count.
* Note, can be 0 if KDF does not need the iteration count.
*/
func (obj *SaltedKdfAlgInfo) IterationCount () uint32 {
    proxyResult := /*pr4*/C.vscf_salted_kdf_alg_info_iteration_count(obj.cCtx)

    return uint32(proxyResult) /* r9 */
}

/* Handle underlying C context. */
func (obj *SaltedKdfAlgInfo) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(obj.cCtx)
}

func NewSaltedKdfAlgInfo () *SaltedKdfAlgInfo {
    ctx := C.vscf_salted_kdf_alg_info_new()
    return &SaltedKdfAlgInfo {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newSaltedKdfAlgInfoWithCtx (ctx *C.vscf_salted_kdf_alg_info_t /*ct10*/) *SaltedKdfAlgInfo {
    return &SaltedKdfAlgInfo {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newSaltedKdfAlgInfoCopy (ctx *C.vscf_salted_kdf_alg_info_t /*ct10*/) *SaltedKdfAlgInfo {
    return &SaltedKdfAlgInfo {
        cCtx: C.vscf_salted_kdf_alg_info_shallow_copy(ctx),
    }
}

/*
* Release underlying C context.
*/
func (obj *SaltedKdfAlgInfo) Delete () {
    C.vscf_salted_kdf_alg_info_delete(obj.cCtx)
}

/*
* Create algorithm info with identificator, HASH algorithm info,
* salt and iteration count.
*/
func NewSaltedKdfAlgInfoWithMembers (algId AlgId, hashAlgInfo IAlgInfo, salt []byte, iterationCount uint32) *SaltedKdfAlgInfo {
    saltData := helperWrapData (salt)

    hashAlgInfoCopy := C.vscf_impl_shallow_copy((*C.vscf_impl_t)(hashAlgInfo.ctx()))

    proxyResult := /*pr4*/C.vscf_salted_kdf_alg_info_new_with_members(C.vscf_alg_id_t(algId) /*pa7*/, &hashAlgInfoCopy, saltData, (C.size_t)(iterationCount)/*pa10*/)

    return &SaltedKdfAlgInfo {
        cCtx: proxyResult,
    }
}

/*
* Provide algorithm identificator.
*/
func (obj *SaltedKdfAlgInfo) AlgId () AlgId {
    proxyResult := /*pr4*/C.vscf_salted_kdf_alg_info_alg_id(obj.cCtx)

    return AlgId(proxyResult) /* r8 */
}
