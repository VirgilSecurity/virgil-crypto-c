package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import "runtime"


/*
* Virgil Security implementation of HMAC algorithm (RFC 2104) (FIPS PUB 198-1).
*/
type Hmac struct {
    cCtx *C.vscf_hmac_t /*ct10*/
}

func (obj *Hmac) SetHash(hash Hash) {
    C.vscf_hmac_release_hash(obj.cCtx)
    C.vscf_hmac_use_hash(obj.cCtx, (*C.vscf_impl_t)(hash.ctx()))
}

/* Handle underlying C context. */
func (obj *Hmac) ctx() *C.vscf_impl_t {
    return (*C.vscf_impl_t)(obj.cCtx)
}

func NewHmac() *Hmac {
    ctx := C.vscf_hmac_new()
    obj := &Hmac {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, obj.Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newHmacWithCtx(ctx *C.vscf_hmac_t /*ct10*/) *Hmac {
    obj := &Hmac {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, obj.Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newHmacCopy(ctx *C.vscf_hmac_t /*ct10*/) *Hmac {
    obj := &Hmac {
        cCtx: C.vscf_hmac_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, obj.Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *Hmac) Delete() {
    runtime.SetFinalizer(obj, nil)
    obj.clear()
}

/*
* Release underlying C context.
*/
func (obj *Hmac) delete() {
    C.vscf_hmac_delete(obj.cCtx)
}

/*
* Provide algorithm identificator.
*/
func (obj *Hmac) AlgId() AlgId {
    proxyResult := /*pr4*/C.vscf_hmac_alg_id(obj.cCtx)

    return AlgId(proxyResult) /* r8 */
}

/*
* Produce object with algorithm information and configuration parameters.
*/
func (obj *Hmac) ProduceAlgInfo() (AlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_hmac_produce_alg_info(obj.cCtx)

    return FoundationImplementationWrapAlgInfo(proxyResult) /* r4 */
}

/*
* Restore algorithm configuration from the given object.
*/
func (obj *Hmac) RestoreAlgInfo(algInfo AlgInfo) error {
    proxyResult := /*pr4*/C.vscf_hmac_restore_alg_info(obj.cCtx, (*C.vscf_impl_t)(algInfo.ctx()))

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}

/*
* Size of the digest (mac output) in bytes.
*/
func (obj *Hmac) DigestLen() uint32 {
    proxyResult := /*pr4*/C.vscf_hmac_digest_len(obj.cCtx)

    return uint32(proxyResult) /* r9 */
}

/*
* Calculate MAC over given data.
*/
func (obj *Hmac) Mac(key []byte, data []byte) []byte {
    macBuf, macBufErr := bufferNewBuffer(int(obj.DigestLen() /* lg2 */))
    if macBufErr != nil {
        return nil
    }
    defer macBuf.Delete()
    keyData := helperWrapData (key)
    dataData := helperWrapData (data)

    C.vscf_hmac_mac(obj.cCtx, keyData, dataData, macBuf.ctx)

    return macBuf.getData() /* r7 */
}

/*
* Start a new MAC.
*/
func (obj *Hmac) Start(key []byte) {
    keyData := helperWrapData (key)

    C.vscf_hmac_start(obj.cCtx, keyData)

    return
}

/*
* Add given data to the MAC.
*/
func (obj *Hmac) Update(data []byte) {
    dataData := helperWrapData (data)

    C.vscf_hmac_update(obj.cCtx, dataData)

    return
}

/*
* Accomplish MAC and return it's result (a message digest).
*/
func (obj *Hmac) Finish() []byte {
    macBuf, macBufErr := bufferNewBuffer(int(obj.DigestLen() /* lg2 */))
    if macBufErr != nil {
        return nil
    }
    defer macBuf.Delete()


    C.vscf_hmac_finish(obj.cCtx, macBuf.ctx)

    return macBuf.getData() /* r7 */
}

/*
* Prepare to authenticate a new message with the same key
* as the previous MAC operation.
*/
func (obj *Hmac) Reset() {
    C.vscf_hmac_reset(obj.cCtx)

    return
}
