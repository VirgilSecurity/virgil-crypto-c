package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"

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
    dataSourceData := C.vsc_data((*C.uint8_t)(&dataSource[0]), C.size_t(len(dataSource)))

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
func (this FakeRandom) close () {
    C.vscf_fake_random_delete(this.cCtx)
}

/*
* Generate random bytes.
* All RNG implementations must be thread-safe.
*/
func (this FakeRandom) Random (dataLen uint32) ([]byte, error) {
    dataCount := C.ulong(dataLen)
    dataMemory := make([]byte, int(C.vsc_buffer_ctx_size() + dataCount))
    dataBuf := (*C.vsc_buffer_t)(unsafe.Pointer(&dataMemory[0]))
    dataData := dataMemory[int(C.vsc_buffer_ctx_size()):]
    C.vsc_buffer_init(dataBuf)
    C.vsc_buffer_use(dataBuf, (*C.byte)(unsafe.Pointer(&dataData[0])), dataCount)
    defer C.vsc_buffer_delete(dataBuf)


    proxyResult := /*pr4*/C.vscf_fake_random_random(this.cCtx, (C.size_t)(dataLen)/*pa10*/, dataBuf)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return dataData[0:C.vsc_buffer_len(dataBuf)] /* r7 */, nil
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
    outCount := C.ulong(len)
    outMemory := make([]byte, int(C.vsc_buffer_ctx_size() + outCount))
    outBuf := (*C.vsc_buffer_t)(unsafe.Pointer(&outMemory[0]))
    outData := outMemory[int(C.vsc_buffer_ctx_size()):]
    C.vsc_buffer_init(outBuf)
    C.vsc_buffer_use(outBuf, (*C.byte)(unsafe.Pointer(&outData[0])), outCount)
    defer C.vsc_buffer_delete(outBuf)


    proxyResult := /*pr4*/C.vscf_fake_random_gather(this.cCtx, (C.size_t)(len)/*pa10*/, outBuf)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return outData[0:C.vsc_buffer_len(outBuf)] /* r7 */, nil
}
