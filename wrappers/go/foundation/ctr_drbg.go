package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"


/*
* Implementation of the RNG using deterministic random bit generators
* based on block ciphers in counter mode (CTR_DRBG from NIST SP800-90A).
* This class is thread-safe if the build option VSCF_MULTI_THREADING was enabled.
*/
type CtrDrbg struct {
    IRandom
    cCtx *C.vscf_ctr_drbg_t /*ct10*/
}

/*
* The interval before reseed is performed by default.
*/
func CtrDrbgGetReseedInterval () uint32 {
    return 10000
}

/*
* The amount of entropy used per seed by default.
*/
func CtrDrbgGetEntropyLen () uint32 {
    return 48
}

func (obj *CtrDrbg) SetEntropySource (entropySource IEntropySource) error {
    C.vscf_ctr_drbg_release_entropy_source(obj.cCtx)
                    proxyResult := C.vscf_ctr_drbg_use_entropy_source(obj.cCtx, (*C.vscf_impl_t)(entropySource.ctx()))

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}

/*
* Setup predefined values to the uninitialized class dependencies.
*/
func (obj *CtrDrbg) SetupDefaults () error {
    proxyResult := /*pr4*/C.vscf_ctr_drbg_setup_defaults(obj.cCtx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}

/*
* Force entropy to be gathered at the beginning of every call to
* the random() method.
* Note, use this if your entropy source has sufficient throughput.
*/
func (obj *CtrDrbg) EnablePredictionResistance () {
    C.vscf_ctr_drbg_enable_prediction_resistance(obj.cCtx)

    return
}

/*
* Sets the reseed interval.
* Default value is reseed interval.
*/
func (obj *CtrDrbg) SetReseedInterval (interval uint32) {
    C.vscf_ctr_drbg_set_reseed_interval(obj.cCtx, (C.size_t)(interval)/*pa10*/)

    return
}

/*
* Sets the amount of entropy grabbed on each seed or reseed.
* The default value is entropy len.
*/
func (obj *CtrDrbg) SetEntropyLen (len uint32) {
    C.vscf_ctr_drbg_set_entropy_len(obj.cCtx, (C.size_t)(len)/*pa10*/)

    return
}

/* Handle underlying C context. */
func (obj *CtrDrbg) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(obj.cCtx)
}

func NewCtrDrbg () *CtrDrbg {
    ctx := C.vscf_ctr_drbg_new()
    return &CtrDrbg {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newCtrDrbgWithCtx (ctx *C.vscf_ctr_drbg_t /*ct10*/) *CtrDrbg {
    return &CtrDrbg {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newCtrDrbgCopy (ctx *C.vscf_ctr_drbg_t /*ct10*/) *CtrDrbg {
    return &CtrDrbg {
        cCtx: C.vscf_ctr_drbg_shallow_copy(ctx),
    }
}

/// Release underlying C context.
func (obj *CtrDrbg) clear () {
    C.vscf_ctr_drbg_delete(obj.cCtx)
}

/*
* Generate random bytes.
* All RNG implementations must be thread-safe.
*/
func (obj *CtrDrbg) Random (dataLen uint32) ([]byte, error) {
    dataBuf, dataBufErr := bufferNewBuffer(int(dataLen))
    if dataBufErr != nil {
        return nil, dataBufErr
    }
    defer dataBuf.clear()


    proxyResult := /*pr4*/C.vscf_ctr_drbg_random(obj.cCtx, (C.size_t)(dataLen)/*pa10*/, dataBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return dataBuf.getData() /* r7 */, nil
}

/*
* Retrieve new seed data from the entropy sources.
*/
func (obj *CtrDrbg) Reseed () error {
    proxyResult := /*pr4*/C.vscf_ctr_drbg_reseed(obj.cCtx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}
