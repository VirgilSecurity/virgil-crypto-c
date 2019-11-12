package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"


/*
* Virgil Security implementation of the PBKDF2 (RFC 8018) algorithm.
*/
type Pkcs5Pbkdf2 struct {
    IAlg
    IKdf
    ISaltedKdf
    cCtx *C.vscf_pkcs5_pbkdf2_t /*ct10*/
}

func (obj *Pkcs5Pbkdf2) SetHmac (hmac IMac) {
    C.vscf_pkcs5_pbkdf2_release_hmac(obj.cCtx)
    C.vscf_pkcs5_pbkdf2_use_hmac(obj.cCtx, (*C.vscf_impl_t)(hmac.ctx()))
}

/*
* Setup predefined values to the uninitialized class dependencies.
*/
func (obj *Pkcs5Pbkdf2) SetupDefaults () {
    C.vscf_pkcs5_pbkdf2_setup_defaults(obj.cCtx)

    return
}

/* Handle underlying C context. */
func (obj *Pkcs5Pbkdf2) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(obj.cCtx)
}

func NewPkcs5Pbkdf2 () *Pkcs5Pbkdf2 {
    ctx := C.vscf_pkcs5_pbkdf2_new()
    return &Pkcs5Pbkdf2 {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newPkcs5Pbkdf2WithCtx (ctx *C.vscf_pkcs5_pbkdf2_t /*ct10*/) *Pkcs5Pbkdf2 {
    return &Pkcs5Pbkdf2 {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newPkcs5Pbkdf2Copy (ctx *C.vscf_pkcs5_pbkdf2_t /*ct10*/) *Pkcs5Pbkdf2 {
    return &Pkcs5Pbkdf2 {
        cCtx: C.vscf_pkcs5_pbkdf2_shallow_copy(ctx),
    }
}

/*
* Release underlying C context.
*/
func (obj *Pkcs5Pbkdf2) Delete () {
    C.vscf_pkcs5_pbkdf2_delete(obj.cCtx)
}

/*
* Provide algorithm identificator.
*/
func (obj *Pkcs5Pbkdf2) AlgId () AlgId {
    proxyResult := /*pr4*/C.vscf_pkcs5_pbkdf2_alg_id(obj.cCtx)

    return AlgId(proxyResult) /* r8 */
}

/*
* Produce object with algorithm information and configuration parameters.
*/
func (obj *Pkcs5Pbkdf2) ProduceAlgInfo () (IAlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_pkcs5_pbkdf2_produce_alg_info(obj.cCtx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Restore algorithm configuration from the given object.
*/
func (obj *Pkcs5Pbkdf2) RestoreAlgInfo (algInfo IAlgInfo) error {
    proxyResult := /*pr4*/C.vscf_pkcs5_pbkdf2_restore_alg_info(obj.cCtx, (*C.vscf_impl_t)(algInfo.ctx()))

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}

/*
* Derive key of the requested length from the given data.
*/
func (obj *Pkcs5Pbkdf2) Derive (data []byte, keyLen uint32) []byte {
    keyBuf, keyBufErr := bufferNewBuffer(int(keyLen))
    if keyBufErr != nil {
        return nil
    }
    defer keyBuf.Delete()
    dataData := helperWrapData (data)

    C.vscf_pkcs5_pbkdf2_derive(obj.cCtx, dataData, (C.size_t)(keyLen)/*pa10*/, keyBuf.ctx)

    return keyBuf.getData() /* r7 */
}

/*
* Prepare algorithm to derive new key.
*/
func (obj *Pkcs5Pbkdf2) Reset (salt []byte, iterationCount uint32) {
    saltData := helperWrapData (salt)

    C.vscf_pkcs5_pbkdf2_reset(obj.cCtx, saltData, (C.size_t)(iterationCount)/*pa10*/)

    return
}

/*
* Setup application specific information (optional).
* Can be empty.
*/
func (obj *Pkcs5Pbkdf2) SetInfo (info []byte) {
    infoData := helperWrapData (info)

    C.vscf_pkcs5_pbkdf2_set_info(obj.cCtx, infoData)

    return
}
