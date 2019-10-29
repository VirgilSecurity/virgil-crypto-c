package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"

/*
* This is MbedTLS implementation of SHA224.
*/
type Sha224 struct {
    IAlg
    IHash
    cCtx *C.vscf_sha224_t /*ct10*/
}

/* Handle underlying C context. */
func (this Sha224) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(this.cCtx)
}

func NewSha224 () *Sha224 {
    ctx := C.vscf_sha224_new()
    return &Sha224 {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newSha224WithCtx (ctx *C.vscf_sha224_t /*ct10*/) *Sha224 {
    return &Sha224 {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newSha224Copy (ctx *C.vscf_sha224_t /*ct10*/) *Sha224 {
    return &Sha224 {
        cCtx: C.vscf_sha224_shallow_copy(ctx),
    }
}

/// Release underlying C context.
func (this Sha224) close () {
    C.vscf_sha224_delete(this.cCtx)
}

/*
* Provide algorithm identificator.
*/
func (this Sha224) AlgId () AlgId {
    proxyResult := /*pr4*/C.vscf_sha224_alg_id(this.cCtx)

    return AlgId(proxyResult) /* r8 */
}

/*
* Produce object with algorithm information and configuration parameters.
*/
func (this Sha224) ProduceAlgInfo () (IAlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_sha224_produce_alg_info(this.cCtx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Restore algorithm configuration from the given object.
*/
func (this Sha224) RestoreAlgInfo (algInfo IAlgInfo) error {
    proxyResult := /*pr4*/C.vscf_sha224_restore_alg_info(this.cCtx, (*C.vscf_impl_t)(algInfo.ctx()))

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}

/*
* Length of the digest (hashing output) in bytes.
*/
func Sha224GetDigestLen () uint32 {
    return 28
}

/*
* Block length of the digest function in bytes.
*/
func Sha224GetBlockLen () uint32 {
    return 64
}

/*
* Calculate hash over given data.
*/
func (this Sha224) Hash (data []byte) []byte {
    digestCount := C.ulong(this.GetDigestLen() /* lg3 */)
    digestMemory := make([]byte, int(C.vsc_buffer_ctx_size() + digestCount))
    digestBuf := (*C.vsc_buffer_t)(unsafe.Pointer(&digestMemory[0]))
    digestData := digestMemory[int(C.vsc_buffer_ctx_size()):]
    C.vsc_buffer_init(digestBuf)
    C.vsc_buffer_use(digestBuf, (*C.byte)(unsafe.Pointer(&digestData[0])), digestCount)
    defer C.vsc_buffer_delete(digestBuf)
    dataData := C.vsc_data((*C.uint8_t)(&data[0]), C.size_t(len(data)))

    C.vscf_sha224_hash(dataData, digestBuf)

    return digestData[0:C.vsc_buffer_len(digestBuf)] /* r7 */
}

/*
* Start a new hashing.
*/
func (this Sha224) Start () {
    C.vscf_sha224_start(this.cCtx)

    return
}

/*
* Add given data to the hash.
*/
func (this Sha224) Update (data []byte) {
    dataData := C.vsc_data((*C.uint8_t)(&data[0]), C.size_t(len(data)))

    C.vscf_sha224_update(this.cCtx, dataData)

    return
}

/*
* Accompilsh hashing and return it's result (a message digest).
*/
func (this Sha224) Finish () []byte {
    digestCount := C.ulong(this.GetDigestLen() /* lg3 */)
    digestMemory := make([]byte, int(C.vsc_buffer_ctx_size() + digestCount))
    digestBuf := (*C.vsc_buffer_t)(unsafe.Pointer(&digestMemory[0]))
    digestData := digestMemory[int(C.vsc_buffer_ctx_size()):]
    C.vsc_buffer_init(digestBuf)
    C.vsc_buffer_use(digestBuf, (*C.byte)(unsafe.Pointer(&digestData[0])), digestCount)
    defer C.vsc_buffer_delete(digestBuf)


    C.vscf_sha224_finish(this.cCtx, digestBuf)

    return digestData[0:C.vsc_buffer_len(digestBuf)] /* r7 */
}
