package foundation

// #cgo CFLAGS: -I${SRCDIR}/../../../build/library/foundation/include/virgil/crypto/foundation
// #cgo CFLAGS: -I${SRCDIR}/../../../library/foundation/include/virgil/crypto/foundation
// #cgo LDFLAGS: -L${SRCDIR}/../../java/binaries/linux/lib -lvscf_foundation_java
// #include <vscf_foundation_public.h>
import "C"
import . "virgil/common"

/*
* Implementation of the RNG using deterministic random bit generators
* based on block ciphers in counter mode (CTR_DRBG from NIST SP800-90A).
* This class is thread-safe if the build option VSCF_MULTI_THREADING was enabled.
*/
type CtrDrbg struct {
    IRandom
    ctx *C.vscf_impl_t
}

/*
* The interval before reseed is performed by default.
*/
func (this CtrDrbg) getReseedInterval () int32 {
    return 10000
}

/*
* The amount of entropy used per seed by default.
*/
func (this CtrDrbg) getEntropyLen () int32 {
    return 48
}

func (this CtrDrbg) SetEntropySource (entropySource IEntropySource) {
    C.vscf_ctr_drbg_release_entropy_source(this.ctx)
    proxyResult := C.vscf_ctr_drbg_use_entropy_source(this.ctx, entropySource.Ctx())
    FoundationErrorHandleStatus(proxyResult)
}

/*
* Setup predefined values to the uninitialized class dependencies.
*/
func (this CtrDrbg) SetupDefaults () {
    proxyResult := C.vscf_ctr_drbg_setup_defaults(this.ctx)

    FoundationErrorHandleStatus(proxyResult)
}

/*
* Force entropy to be gathered at the beginning of every call to
* the random() method.
* Note, use this if your entropy source has sufficient throughput.
*/
func (this CtrDrbg) EnablePredictionResistance () {
    C.vscf_ctr_drbg_enable_prediction_resistance(this.ctx)
}

/*
* Sets the reseed interval.
* Default value is reseed interval.
*/
func (this CtrDrbg) SetReseedInterval (interval int32) {
    C.vscf_ctr_drbg_set_reseed_interval(this.ctx, interval)
}

/*
* Sets the amount of entropy grabbed on each seed or reseed.
* The default value is entropy len.
*/
func (this CtrDrbg) SetEntropyLen (len int32) {
    C.vscf_ctr_drbg_set_entropy_len(this.ctx, len)
}

/* Handle underlying C context. */
func (this CtrDrbg) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewCtrDrbg () *CtrDrbg {
    ctx := C.vscf_ctr_drbg_new()
    return &CtrDrbg {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewCtrDrbgWithCtx (ctx *C.vscf_impl_t) *CtrDrbg {
    return &CtrDrbg {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewCtrDrbgCopy (ctx *C.vscf_impl_t) *CtrDrbg {
    return &CtrDrbg {
        ctx: C.vscf_ctr_drbg_shallow_copy(ctx),
    }
}

/*
* Generate random bytes.
* All RNG implementations must be thread-safe.
*/
func (this CtrDrbg) Random (dataLen int32) []byte {
    dataCount := dataLen
    dataBuf := NewBuffer(dataCount)
    defer dataBuf.Clear()


    proxyResult := C.vscf_ctr_drbg_random(this.ctx, dataLen, dataBuf)

    FoundationErrorHandleStatus(proxyResult)

    return dataBuf.GetData() /* r7 */
}

/*
* Retrieve new seed data from the entropy sources.
*/
func (this CtrDrbg) Reseed () {
    proxyResult := C.vscf_ctr_drbg_reseed(this.ctx)

    FoundationErrorHandleStatus(proxyResult)
}
