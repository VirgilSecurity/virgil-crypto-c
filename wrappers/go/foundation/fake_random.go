package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_common
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_foundation
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import . "virgil/common"

/*
* Random number generator that is used for test purposes only.
*/
type FakeRandom struct {
    IRandom
    IEntropySource
    ctx *C.vscf_impl_t
}

/*
* Configure random number generator to generate sequence filled with given byte.
*/
func (this FakeRandom) SetupSourceByte (byteSource byte) {
    C.vscf_fake_random_setup_source_byte(this.ctx, byteSource)
}

/*
* Configure random number generator to generate random sequence from given data.
* Note, that given data is used as circular source.
*/
func (this FakeRandom) SetupSourceData (dataSource []byte) {
    C.vscf_fake_random_setup_source_data(this.ctx, WrapData(dataSource))
}

/* Handle underlying C context. */
func (this FakeRandom) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewFakeRandom () *FakeRandom {
    ctx := C.vscf_fake_random_new()
    return &FakeRandom {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewFakeRandomWithCtx (ctx *C.vscf_impl_t) *FakeRandom {
    return &FakeRandom {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewFakeRandomCopy (ctx *C.vscf_impl_t) *FakeRandom {
    return &FakeRandom {
        ctx: C.vscf_fake_random_shallow_copy(ctx),
    }
}

/*
* Generate random bytes.
* All RNG implementations must be thread-safe.
*/
func (this FakeRandom) Random (dataLen int32) []byte {
    dataCount := dataLen
    dataBuf := NewBuffer(dataCount)
    defer dataBuf.Clear()


    proxyResult := C.vscf_fake_random_random(this.ctx, dataLen, dataBuf)

    FoundationErrorHandleStatus(proxyResult)

    return dataBuf.GetData() /* r7 */
}

/*
* Retrieve new seed data from the entropy sources.
*/
func (this FakeRandom) Reseed () {
    proxyResult := C.vscf_fake_random_reseed(this.ctx)

    FoundationErrorHandleStatus(proxyResult)
}

/*
* Defines that implemented source is strong.
*/
func (this FakeRandom) IsStrong () bool {
    proxyResult := C.vscf_fake_random_is_strong(this.ctx)

    return proxyResult //r9
}

/*
* Gather entropy of the requested length.
*/
func (this FakeRandom) Gather (len int32) []byte {
    outCount := len
    outBuf := NewBuffer(outCount)
    defer outBuf.Clear()


    proxyResult := C.vscf_fake_random_gather(this.ctx, len, outBuf)

    FoundationErrorHandleStatus(proxyResult)

    return outBuf.GetData() /* r7 */
}
