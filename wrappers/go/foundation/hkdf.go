package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"


/*
* Virgil Security implementation of the HKDF (RFC 6234) algorithm.
*/
type Hkdf struct {
    IAlg
    IKdf
    ISaltedKdf
    cCtx *C.vscf_hkdf_t /*ct10*/
}

func HkdfGetHashCounterMax () uint32 {
    return 255
}

func (this Hkdf) SetHash (hash IHash) {
    C.vscf_hkdf_release_hash(this.cCtx)
    C.vscf_hkdf_use_hash(this.cCtx, (*C.vscf_impl_t)(hash.ctx()))
}

/* Handle underlying C context. */
func (this Hkdf) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(this.cCtx)
}

func NewHkdf () *Hkdf {
    ctx := C.vscf_hkdf_new()
    return &Hkdf {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newHkdfWithCtx (ctx *C.vscf_hkdf_t /*ct10*/) *Hkdf {
    return &Hkdf {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newHkdfCopy (ctx *C.vscf_hkdf_t /*ct10*/) *Hkdf {
    return &Hkdf {
        cCtx: C.vscf_hkdf_shallow_copy(ctx),
    }
}

/// Release underlying C context.
func (this Hkdf) clear () {
    C.vscf_hkdf_delete(this.cCtx)
}

/*
* Provide algorithm identificator.
*/
func (this Hkdf) AlgId () AlgId {
    proxyResult := /*pr4*/C.vscf_hkdf_alg_id(this.cCtx)

    return AlgId(proxyResult) /* r8 */
}

/*
* Produce object with algorithm information and configuration parameters.
*/
func (this Hkdf) ProduceAlgInfo () (IAlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_hkdf_produce_alg_info(this.cCtx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Restore algorithm configuration from the given object.
*/
func (this Hkdf) RestoreAlgInfo (algInfo IAlgInfo) error {
    proxyResult := /*pr4*/C.vscf_hkdf_restore_alg_info(this.cCtx, (*C.vscf_impl_t)(algInfo.ctx()))

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}

/*
* Derive key of the requested length from the given data.
*/
func (this Hkdf) Derive (data []byte, keyLen uint32) []byte {
    keyBuf, keyBufErr := bufferNewBuffer(int(keyLen))
    if keyBufErr != nil {
        return nil
    }
    defer keyBuf.clear()
    dataData := helperWrapData (data)

    C.vscf_hkdf_derive(this.cCtx, dataData, (C.size_t)(keyLen)/*pa10*/, keyBuf.ctx)

    return keyBuf.getData() /* r7 */
}

/*
* Prepare algorithm to derive new key.
*/
func (this Hkdf) Reset (salt []byte, iterationCount uint32) {
    saltData := helperWrapData (salt)

    C.vscf_hkdf_reset(this.cCtx, saltData, (C.size_t)(iterationCount)/*pa10*/)

    return
}

/*
* Setup application specific information (optional).
* Can be empty.
*/
func (this Hkdf) SetInfo (info []byte) {
    infoData := helperWrapData (info)

    C.vscf_hkdf_set_info(this.cCtx, infoData)

    return
}
