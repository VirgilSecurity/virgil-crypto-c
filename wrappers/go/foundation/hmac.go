package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"

/*
* Virgil Security implementation of HMAC algorithm (RFC 2104) (FIPS PUB 198-1).
*/
type Hmac struct {
    IAlg
    IMac
    cCtx *C.vscf_hmac_t /*ct10*/
}

func (this Hmac) SetHash (hash IHash) {
    C.vscf_hmac_release_hash(this.cCtx)
    C.vscf_hmac_use_hash(this.cCtx, (*C.vscf_impl_t)(hash.ctx()))
}

/* Handle underlying C context. */
func (this Hmac) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(this.cCtx)
}

func NewHmac () *Hmac {
    ctx := C.vscf_hmac_new()
    return &Hmac {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newHmacWithCtx (ctx *C.vscf_hmac_t /*ct10*/) *Hmac {
    return &Hmac {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newHmacCopy (ctx *C.vscf_hmac_t /*ct10*/) *Hmac {
    return &Hmac {
        cCtx: C.vscf_hmac_shallow_copy(ctx),
    }
}

/// Release underlying C context.
func (this Hmac) close () {
    C.vscf_hmac_delete(this.cCtx)
}

/*
* Provide algorithm identificator.
*/
func (this Hmac) AlgId () AlgId {
    proxyResult := /*pr4*/C.vscf_hmac_alg_id(this.cCtx)

    return AlgId(proxyResult) /* r8 */
}

/*
* Produce object with algorithm information and configuration parameters.
*/
func (this Hmac) ProduceAlgInfo () (IAlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_hmac_produce_alg_info(this.cCtx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Restore algorithm configuration from the given object.
*/
func (this Hmac) RestoreAlgInfo (algInfo IAlgInfo) error {
    proxyResult := /*pr4*/C.vscf_hmac_restore_alg_info(this.cCtx, (*C.vscf_impl_t)(algInfo.ctx()))

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}

/*
* Size of the digest (mac output) in bytes.
*/
func (this Hmac) DigestLen () uint32 {
    proxyResult := /*pr4*/C.vscf_hmac_digest_len(this.cCtx)

    return uint32(proxyResult) /* r9 */
}

/*
* Calculate MAC over given data.
*/
func (this Hmac) Mac (key []byte, data []byte) []byte {
    macCount := C.ulong(this.DigestLen() /* lg2 */)
    macMemory := make([]byte, int(C.vsc_buffer_ctx_size() + macCount))
    macBuf := (*C.vsc_buffer_t)(unsafe.Pointer(&macMemory[0]))
    macData := macMemory[int(C.vsc_buffer_ctx_size()):]
    C.vsc_buffer_init(macBuf)
    C.vsc_buffer_use(macBuf, (*C.byte)(unsafe.Pointer(&macData[0])), macCount)
    defer C.vsc_buffer_delete(macBuf)
    keyData := C.vsc_data((*C.uint8_t)(&key[0]), C.size_t(len(key)))
    dataData := C.vsc_data((*C.uint8_t)(&data[0]), C.size_t(len(data)))

    C.vscf_hmac_mac(this.cCtx, keyData, dataData, macBuf)

    return macData[0:C.vsc_buffer_len(macBuf)] /* r7 */
}

/*
* Start a new MAC.
*/
func (this Hmac) Start (key []byte) {
    keyData := C.vsc_data((*C.uint8_t)(&key[0]), C.size_t(len(key)))

    C.vscf_hmac_start(this.cCtx, keyData)

    return
}

/*
* Add given data to the MAC.
*/
func (this Hmac) Update (data []byte) {
    dataData := C.vsc_data((*C.uint8_t)(&data[0]), C.size_t(len(data)))

    C.vscf_hmac_update(this.cCtx, dataData)

    return
}

/*
* Accomplish MAC and return it's result (a message digest).
*/
func (this Hmac) Finish () []byte {
    macCount := C.ulong(this.DigestLen() /* lg2 */)
    macMemory := make([]byte, int(C.vsc_buffer_ctx_size() + macCount))
    macBuf := (*C.vsc_buffer_t)(unsafe.Pointer(&macMemory[0]))
    macData := macMemory[int(C.vsc_buffer_ctx_size()):]
    C.vsc_buffer_init(macBuf)
    C.vsc_buffer_use(macBuf, (*C.byte)(unsafe.Pointer(&macData[0])), macCount)
    defer C.vsc_buffer_delete(macBuf)


    C.vscf_hmac_finish(this.cCtx, macBuf)

    return macData[0:C.vsc_buffer_len(macBuf)] /* r7 */
}

/*
* Prepare to authenticate a new message with the same key
* as the previous MAC operation.
*/
func (this Hmac) Reset () {
    C.vscf_hmac_reset(this.cCtx)

    return
}
