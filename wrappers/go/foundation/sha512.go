package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"


/*
* This is MbedTLS implementation of SHA512.
*/
type Sha512 struct {
    IAlg
    IHash
    cCtx *C.vscf_sha512_t /*ct10*/
}

/* Handle underlying C context. */
func (this Sha512) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(this.cCtx)
}

func NewSha512 () *Sha512 {
    ctx := C.vscf_sha512_new()
    return &Sha512 {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newSha512WithCtx (ctx *C.vscf_sha512_t /*ct10*/) *Sha512 {
    return &Sha512 {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newSha512Copy (ctx *C.vscf_sha512_t /*ct10*/) *Sha512 {
    return &Sha512 {
        cCtx: C.vscf_sha512_shallow_copy(ctx),
    }
}

/// Release underlying C context.
func (this Sha512) clear () {
    C.vscf_sha512_delete(this.cCtx)
}

/*
* Provide algorithm identificator.
*/
func (this Sha512) AlgId () AlgId {
    proxyResult := /*pr4*/C.vscf_sha512_alg_id(this.cCtx)

    return AlgId(proxyResult) /* r8 */
}

/*
* Produce object with algorithm information and configuration parameters.
*/
func (this Sha512) ProduceAlgInfo () (IAlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_sha512_produce_alg_info(this.cCtx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Restore algorithm configuration from the given object.
*/
func (this Sha512) RestoreAlgInfo (algInfo IAlgInfo) error {
    proxyResult := /*pr4*/C.vscf_sha512_restore_alg_info(this.cCtx, (*C.vscf_impl_t)(algInfo.ctx()))

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}

/*
* Length of the digest (hashing output) in bytes.
*/
func (this Sha512) GetDigestLen () uint32 {
    return 64
}

/*
* Block length of the digest function in bytes.
*/
func (this Sha512) GetBlockLen () uint32 {
    return 128
}

/*
* Calculate hash over given data.
*/
func (this Sha512) Hash (data []byte) []byte {
    digestBuf, digestBufErr := bufferNewBuffer(int(this.GetDigestLen() /* lg3 */))
    if digestBufErr != nil {
        return nil
    }
    defer digestBuf.clear()
    dataData := helperWrapData (data)

    C.vscf_sha512_hash(dataData, digestBuf.ctx)

    return digestBuf.getData() /* r7 */
}

/*
* Start a new hashing.
*/
func (this Sha512) Start () {
    C.vscf_sha512_start(this.cCtx)

    return
}

/*
* Add given data to the hash.
*/
func (this Sha512) Update (data []byte) {
    dataData := helperWrapData (data)

    C.vscf_sha512_update(this.cCtx, dataData)

    return
}

/*
* Accompilsh hashing and return it's result (a message digest).
*/
func (this Sha512) Finish () []byte {
    digestBuf, digestBufErr := bufferNewBuffer(int(this.GetDigestLen() /* lg3 */))
    if digestBufErr != nil {
        return nil
    }
    defer digestBuf.clear()


    C.vscf_sha512_finish(this.cCtx, digestBuf.ctx)

    return digestBuf.getData() /* r7 */
}
