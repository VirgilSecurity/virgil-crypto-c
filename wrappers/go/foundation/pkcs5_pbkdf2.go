package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"

/*
* Virgil Security implementation of the PBKDF2 (RFC 8018) algorithm.
*/
type Pkcs5Pbkdf2 struct {
    IAlg
    IKdf
    ISaltedKdf
    cCtx *C.vscf_pkcs5_pbkdf2_t /*ct10*/
}

func (this Pkcs5Pbkdf2) SetHmac (hmac IMac) {
    C.vscf_pkcs5_pbkdf2_release_hmac(this.cCtx)
    C.vscf_pkcs5_pbkdf2_use_hmac(this.cCtx, (*C.vscf_impl_t)(hmac.ctx()))
}

/*
* Setup predefined values to the uninitialized class dependencies.
*/
func (this Pkcs5Pbkdf2) SetupDefaults () {
    C.vscf_pkcs5_pbkdf2_setup_defaults(this.cCtx)

    return
}

/* Handle underlying C context. */
func (this Pkcs5Pbkdf2) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(this.cCtx)
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

/// Release underlying C context.
func (this Pkcs5Pbkdf2) close () {
    C.vscf_pkcs5_pbkdf2_delete(this.cCtx)
}

/*
* Provide algorithm identificator.
*/
func (this Pkcs5Pbkdf2) AlgId () AlgId {
    proxyResult := /*pr4*/C.vscf_pkcs5_pbkdf2_alg_id(this.cCtx)

    return AlgId(proxyResult) /* r8 */
}

/*
* Produce object with algorithm information and configuration parameters.
*/
func (this Pkcs5Pbkdf2) ProduceAlgInfo () (IAlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_pkcs5_pbkdf2_produce_alg_info(this.cCtx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Restore algorithm configuration from the given object.
*/
func (this Pkcs5Pbkdf2) RestoreAlgInfo (algInfo IAlgInfo) error {
    proxyResult := /*pr4*/C.vscf_pkcs5_pbkdf2_restore_alg_info(this.cCtx, (*C.vscf_impl_t)(algInfo.ctx()))

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}

/*
* Derive key of the requested length from the given data.
*/
func (this Pkcs5Pbkdf2) Derive (data []byte, keyLen uint32) []byte {
    keyCount := C.ulong(keyLen)
    keyMemory := make([]byte, int(C.vsc_buffer_ctx_size() + keyCount))
    keyBuf := (*C.vsc_buffer_t)(unsafe.Pointer(&keyMemory[0]))
    keyData := keyMemory[int(C.vsc_buffer_ctx_size()):]
    C.vsc_buffer_init(keyBuf)
    C.vsc_buffer_use(keyBuf, (*C.byte)(unsafe.Pointer(&keyData[0])), keyCount)
    defer C.vsc_buffer_delete(keyBuf)
    dataData := C.vsc_data((*C.uint8_t)(&data[0]), C.size_t(len(data)))

    C.vscf_pkcs5_pbkdf2_derive(this.cCtx, dataData, (C.size_t)(keyLen)/*pa10*/, keyBuf)

    return keyData[0:C.vsc_buffer_len(keyBuf)] /* r7 */
}

/*
* Prepare algorithm to derive new key.
*/
func (this Pkcs5Pbkdf2) Reset (salt []byte, iterationCount uint32) {
    saltData := C.vsc_data((*C.uint8_t)(&salt[0]), C.size_t(len(salt)))

    C.vscf_pkcs5_pbkdf2_reset(this.cCtx, saltData, (C.size_t)(iterationCount)/*pa10*/)

    return
}

/*
* Setup application specific information (optional).
* Can be empty.
*/
func (this Pkcs5Pbkdf2) SetInfo (info []byte) {
    infoData := C.vsc_data((*C.uint8_t)(&info[0]), C.size_t(len(info)))

    C.vscf_pkcs5_pbkdf2_set_info(this.cCtx, infoData)

    return
}
