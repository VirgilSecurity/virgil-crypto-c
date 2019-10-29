package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"

/*
* This is MbedTLS implementation of SHA384.
*/
type Sha384 struct {
    IAlg
    IHash
    cCtx *C.vscf_sha384_t /*ct10*/
}

/* Handle underlying C context. */
func (this Sha384) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(this.cCtx)
}

func NewSha384 () *Sha384 {
    ctx := C.vscf_sha384_new()
    return &Sha384 {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newSha384WithCtx (ctx *C.vscf_sha384_t /*ct10*/) *Sha384 {
    return &Sha384 {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newSha384Copy (ctx *C.vscf_sha384_t /*ct10*/) *Sha384 {
    return &Sha384 {
        cCtx: C.vscf_sha384_shallow_copy(ctx),
    }
}

/// Release underlying C context.
func (this Sha384) close () {
    C.vscf_sha384_delete(this.cCtx)
}

/*
* Provide algorithm identificator.
*/
func (this Sha384) AlgId () AlgId {
    proxyResult := /*pr4*/C.vscf_sha384_alg_id(this.cCtx)

    return AlgId(proxyResult) /* r8 */
}

/*
* Produce object with algorithm information and configuration parameters.
*/
func (this Sha384) ProduceAlgInfo () (IAlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_sha384_produce_alg_info(this.cCtx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Restore algorithm configuration from the given object.
*/
func (this Sha384) RestoreAlgInfo (algInfo IAlgInfo) error {
    proxyResult := /*pr4*/C.vscf_sha384_restore_alg_info(this.cCtx, (*C.vscf_impl_t)(algInfo.ctx()))

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}

/*
* Length of the digest (hashing output) in bytes.
*/
func Sha384GetDigestLen () uint32 {
    return 48
}

/*
* Block length of the digest function in bytes.
*/
func Sha384GetBlockLen () uint32 {
    return 128
}

/*
* Calculate hash over given data.
*/
func (this Sha384) Hash (data []byte) []byte {
    digestCount := C.ulong(this.GetDigestLen() /* lg3 */)
    digestMemory := make([]byte, int(C.vsc_buffer_ctx_size() + digestCount))
    digestBuf := (*C.vsc_buffer_t)(unsafe.Pointer(&digestMemory[0]))
    digestData := digestMemory[int(C.vsc_buffer_ctx_size()):]
    C.vsc_buffer_init(digestBuf)
    C.vsc_buffer_use(digestBuf, (*C.byte)(unsafe.Pointer(&digestData[0])), digestCount)
    defer C.vsc_buffer_delete(digestBuf)
    dataData := C.vsc_data((*C.uint8_t)(&data[0]), C.size_t(len(data)))

    C.vscf_sha384_hash(dataData, digestBuf)

    return digestData[0:C.vsc_buffer_len(digestBuf)] /* r7 */
}

/*
* Start a new hashing.
*/
func (this Sha384) Start () {
    C.vscf_sha384_start(this.cCtx)

    return
}

/*
* Add given data to the hash.
*/
func (this Sha384) Update (data []byte) {
    dataData := C.vsc_data((*C.uint8_t)(&data[0]), C.size_t(len(data)))

    C.vscf_sha384_update(this.cCtx, dataData)

    return
}

/*
* Accompilsh hashing and return it's result (a message digest).
*/
func (this Sha384) Finish () []byte {
    digestCount := C.ulong(this.GetDigestLen() /* lg3 */)
    digestMemory := make([]byte, int(C.vsc_buffer_ctx_size() + digestCount))
    digestBuf := (*C.vsc_buffer_t)(unsafe.Pointer(&digestMemory[0]))
    digestData := digestMemory[int(C.vsc_buffer_ctx_size()):]
    C.vsc_buffer_init(digestBuf)
    C.vsc_buffer_use(digestBuf, (*C.byte)(unsafe.Pointer(&digestData[0])), digestCount)
    defer C.vsc_buffer_delete(digestBuf)


    C.vscf_sha384_finish(this.cCtx, digestBuf)

    return digestData[0:C.vsc_buffer_len(digestBuf)] /* r7 */
}
