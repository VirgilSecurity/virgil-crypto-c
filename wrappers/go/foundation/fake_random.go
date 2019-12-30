package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import "runtime"
import unsafe "unsafe"


/*
* Random number generator that is used for test purposes only.
*/
type FakeRandom struct {
    cCtx *C.vscf_fake_random_t /*ct10*/
}

/*
* Configure random number generator to generate sequence filled with given byte.
*/
func (obj *FakeRandom) SetupSourceByte(byteSource byte) {
    C.vscf_fake_random_setup_source_byte(obj.cCtx, (C.byte)(byteSource)/*pa10*/)

    runtime.KeepAlive(obj)

    return
}

/*
* Configure random number generator to generate random sequence from given data.
* Note, that given data is used as circular source.
*/
func (obj *FakeRandom) SetupSourceData(dataSource []byte) {
    dataSourceData := helperWrapData (dataSource)

    C.vscf_fake_random_setup_source_data(obj.cCtx, dataSourceData)

    runtime.KeepAlive(obj)

    return
}

/* Handle underlying C context. */
func (obj *FakeRandom) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewFakeRandom() *FakeRandom {
    ctx := C.vscf_fake_random_new()
    obj := &FakeRandom {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*FakeRandom).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newFakeRandomWithCtx(ctx *C.vscf_fake_random_t /*ct10*/) *FakeRandom {
    obj := &FakeRandom {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*FakeRandom).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newFakeRandomCopy(ctx *C.vscf_fake_random_t /*ct10*/) *FakeRandom {
    obj := &FakeRandom {
        cCtx: C.vscf_fake_random_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*FakeRandom).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *FakeRandom) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *FakeRandom) delete() {
    C.vscf_fake_random_delete(obj.cCtx)
}

/*
* Generate random bytes.
* All RNG implementations must be thread-safe.
*/
func (obj *FakeRandom) Random(dataLen uint) ([]byte, error) {
    dataBuf, dataBufErr := bufferNewBuffer(int(dataLen))
    if dataBufErr != nil {
        return nil, dataBufErr
    }
    defer dataBuf.Delete()


    proxyResult := /*pr4*/C.vscf_fake_random_random(obj.cCtx, (C.size_t)(dataLen)/*pa10*/, dataBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return dataBuf.getData() /* r7 */, nil
}

/*
* Retrieve new seed data from the entropy sources.
*/
func (obj *FakeRandom) Reseed() error {
    proxyResult := /*pr4*/C.vscf_fake_random_reseed(obj.cCtx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    runtime.KeepAlive(obj)

    return nil
}

/*
* Defines that implemented source is strong.
*/
func (obj *FakeRandom) IsStrong() bool {
    proxyResult := /*pr4*/C.vscf_fake_random_is_strong(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Gather entropy of the requested length.
*/
func (obj *FakeRandom) Gather(len uint) ([]byte, error) {
    outBuf, outBufErr := bufferNewBuffer(int(len))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.Delete()


    proxyResult := /*pr4*/C.vscf_fake_random_gather(obj.cCtx, (C.size_t)(len)/*pa10*/, outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return outBuf.getData() /* r7 */, nil
}
