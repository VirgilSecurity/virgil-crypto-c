package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"

/*
* Virgil Security implementation of the KDF2 (ISO-18033-2) algorithm.
*/
type Kdf2 struct {
    IAlg
    IKdf
    cCtx *C.vscf_kdf2_t /*ct10*/
}

func (this Kdf2) SetHash (hash IHash) {
    C.vscf_kdf2_release_hash(this.cCtx)
    C.vscf_kdf2_use_hash(this.cCtx, (*C.vscf_impl_t)(hash.ctx()))
}

/* Handle underlying C context. */
func (this Kdf2) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(this.cCtx)
}

func NewKdf2 () *Kdf2 {
    ctx := C.vscf_kdf2_new()
    return &Kdf2 {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newKdf2WithCtx (ctx *C.vscf_kdf2_t /*ct10*/) *Kdf2 {
    return &Kdf2 {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newKdf2Copy (ctx *C.vscf_kdf2_t /*ct10*/) *Kdf2 {
    return &Kdf2 {
        cCtx: C.vscf_kdf2_shallow_copy(ctx),
    }
}

/// Release underlying C context.
func (this Kdf2) close () {
    C.vscf_kdf2_delete(this.cCtx)
}

/*
* Provide algorithm identificator.
*/
func (this Kdf2) AlgId () AlgId {
    proxyResult := /*pr4*/C.vscf_kdf2_alg_id(this.cCtx)

    return AlgId(proxyResult) /* r8 */
}

/*
* Produce object with algorithm information and configuration parameters.
*/
func (this Kdf2) ProduceAlgInfo () (IAlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_kdf2_produce_alg_info(this.cCtx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Restore algorithm configuration from the given object.
*/
func (this Kdf2) RestoreAlgInfo (algInfo IAlgInfo) error {
    proxyResult := /*pr4*/C.vscf_kdf2_restore_alg_info(this.cCtx, (*C.vscf_impl_t)(algInfo.ctx()))

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}

/*
* Derive key of the requested length from the given data.
*/
func (this Kdf2) Derive (data []byte, keyLen uint32) []byte {
    keyCount := C.ulong(keyLen)
    keyMemory := make([]byte, int(C.vsc_buffer_ctx_size() + keyCount))
    keyBuf := (*C.vsc_buffer_t)(unsafe.Pointer(&keyMemory[0]))
    keyData := keyMemory[int(C.vsc_buffer_ctx_size()):]
    C.vsc_buffer_init(keyBuf)
    C.vsc_buffer_use(keyBuf, (*C.byte)(unsafe.Pointer(&keyData[0])), keyCount)
    defer C.vsc_buffer_delete(keyBuf)
    dataData := C.vsc_data((*C.uint8_t)(&data[0]), C.size_t(len(data)))

    C.vscf_kdf2_derive(this.cCtx, dataData, (C.size_t)(keyLen)/*pa10*/, keyBuf)

    return keyData[0:C.vsc_buffer_len(keyBuf)] /* r7 */
}
