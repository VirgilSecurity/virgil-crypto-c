package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"


/*
* Random number generator that is used for test purposes only.
*/
type FakeRandom struct {
    IRandom
    IEntropySource
    cCtx *C.vscf_fake_random_t /*ct10*/
}

/*
* Configure random number generator to generate sequence filled with given byte.
*/
func (this FakeRandom) SetupSourceByte (byteSource byte) {
    C.vscf_fake_random_setup_source_byte(this.cCtx, (C.byte)(byteSource)/*pa10*/)

    return
}

/*
* Configure random number generator to generate random sequence from given data.
* Note, that given data is used as circular source.
*/
func (this FakeRandom) SetupSourceData (dataSource []byte) {
    dataSourceData := helperWrapData (dataSource)

    C.vscf_fake_random_setup_source_data(this.cCtx, dataSourceData)

    return
}

/* Handle underlying C context. */
func (this FakeRandom) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(this.cCtx)
}

func NewFakeRandom () *FakeRandom {
    ctx := C.vscf_fake_random_new()
    return &FakeRandom {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newFakeRandomWithCtx (ctx *C.vscf_fake_random_t /*ct10*/) *FakeRandom {
    return &FakeRandom {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newFakeRandomCopy (ctx *C.vscf_fake_random_t /*ct10*/) *FakeRandom {
    return &FakeRandom {
        cCtx: C.vscf_fake_random_shallow_copy(ctx),
    }
}

/// Release underlying C context.
func (this FakeRandom) clear () {
    C.vscf_fake_random_delete(this.cCtx)
}

/*
* Generate random bytes.
* All RNG implementations must be thread-safe.
*/
func (this FakeRandom) Random (dataLen uint32) ([]byte, error) {
    dataBuf, dataBufErr := bufferNewBuffer(int(dataLen))
    if dataBufErr != nil {
        return nil, dataBufErr
    }
    defer dataBuf.clear()


    proxyResult := /*pr4*/C.vscf_fake_random_random(this.cCtx, (C.size_t)(dataLen)/*pa10*/, dataBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return dataBuf.getData() /* r7 */, nil
}

/*
* Retrieve new seed data from the entropy sources.
*/
func (this FakeRandom) Reseed () error {
    proxyResult := /*pr4*/C.vscf_fake_random_reseed(this.cCtx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}

/*
* Defines that implemented source is strong.
*/
func (this FakeRandom) IsStrong () bool {
    proxyResult := /*pr4*/C.vscf_fake_random_is_strong(this.cCtx)

    return bool(proxyResult) /* r9 */
}

/*
* Gather entropy of the requested length.
*/
func (this FakeRandom) Gather (len uint32) ([]byte, error) {
    outBuf, outBufErr := bufferNewBuffer(int(len))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.clear()


    proxyResult := /*pr4*/C.vscf_fake_random_gather(this.cCtx, (C.size_t)(len)/*pa10*/, outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return outBuf.getData() /* r7 */, nil
}
