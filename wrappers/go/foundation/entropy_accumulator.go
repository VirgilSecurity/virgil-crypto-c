package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import "runtime"
import unsafe "unsafe"

/*
* Implementation based on a simple entropy accumulator.
 */
type EntropyAccumulator struct {
	cCtx *C.vscf_entropy_accumulator_t /*ct10*/
}

const (
	EntropyAccumulatorSourcesMax uint = 15
)

/*
* Setup predefined values to the uninitialized class dependencies.
 */
func (obj *EntropyAccumulator) SetupDefaults() {
	C.vscf_entropy_accumulator_setup_defaults(obj.cCtx)

	runtime.KeepAlive(obj)

	return
}

/*
* Add given entropy source to the accumulator.
* Threshold defines minimum number of bytes that must be gathered
* from the source during accumulation.
 */
func (obj *EntropyAccumulator) AddSource(source EntropySource, threshold uint) {
	C.vscf_entropy_accumulator_add_source(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(source.Ctx())), (C.size_t)(threshold) /*pa10*/)

	runtime.KeepAlive(obj)

	runtime.KeepAlive(source)

	return
}

/* Handle underlying C context. */
func (obj *EntropyAccumulator) Ctx() uintptr {
	return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewEntropyAccumulator() *EntropyAccumulator {
	ctx := C.vscf_entropy_accumulator_new()
	obj := &EntropyAccumulator{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*EntropyAccumulator).Delete)
	return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewEntropyAccumulatorWithCtx(anyctx interface{}) *EntropyAccumulator {
	ctx, ok := anyctx.(*C.vscf_entropy_accumulator_t /*ct10*/)
	if !ok {
		return nil //TODO, &FoundationError{-1,"Cast error for struct EntropyAccumulator."}
	}
	obj := &EntropyAccumulator{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*EntropyAccumulator).Delete)
	return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewEntropyAccumulatorCopy(anyctx interface{}) *EntropyAccumulator {
	ctx, ok := anyctx.(*C.vscf_entropy_accumulator_t /*ct10*/)
	if !ok {
		return nil //TODO, &FoundationError{-1,"Cast error for struct EntropyAccumulator."}
	}
	obj := &EntropyAccumulator{
		cCtx: C.vscf_entropy_accumulator_shallow_copy(ctx),
	}
	runtime.SetFinalizer(obj, (*EntropyAccumulator).Delete)
	return obj
}

/*
* Release underlying C context.
 */
func (obj *EntropyAccumulator) Delete() {
	if obj == nil {
		return
	}
	runtime.SetFinalizer(obj, nil)
	obj.delete()
}

/*
* Release underlying C context.
 */
func (obj *EntropyAccumulator) delete() {
	C.vscf_entropy_accumulator_delete(obj.cCtx)
}

/*
* Defines that implemented source is strong.
 */
func (obj *EntropyAccumulator) IsStrong() bool {
	proxyResult := /*pr4*/ C.vscf_entropy_accumulator_is_strong(obj.cCtx)

	runtime.KeepAlive(obj)

	return bool(proxyResult) /* r9 */
}

/*
* Gather entropy of the requested length.
 */
func (obj *EntropyAccumulator) Gather(len uint) ([]byte, error) {
	outBuf, outBufErr := newBuffer(int(len))
	if outBufErr != nil {
		return nil, outBufErr
	}
	defer outBuf.delete()

	proxyResult := /*pr4*/ C.vscf_entropy_accumulator_gather(obj.cCtx, (C.size_t)(len) /*pa10*/, outBuf.ctx)

	err := FoundationErrorHandleStatus(proxyResult)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(obj)

	return outBuf.getData() /* r7 */, nil
}
