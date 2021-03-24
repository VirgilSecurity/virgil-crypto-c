package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"

/*
* Verify data of any size.
* Compatible with the class "signer".
 */
type Verifier struct {
	cCtx *C.vscf_verifier_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *Verifier) Ctx() uintptr {
	return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewVerifier() *Verifier {
	ctx := C.vscf_verifier_new()
	obj := &Verifier{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*Verifier).Delete)
	return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewVerifierWithCtx(pointer unsafe.Pointer) *Verifier {
	ctx := (*C.vscf_verifier_t /*ct2*/)(pointer)
	obj := &Verifier{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*Verifier).Delete)
	return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewVerifierCopy(pointer unsafe.Pointer) *Verifier {
	ctx := (*C.vscf_verifier_t /*ct2*/)(pointer)
	obj := &Verifier{
		cCtx: C.vscf_verifier_shallow_copy(ctx),
	}
	runtime.SetFinalizer(obj, (*Verifier).Delete)
	return obj
}

/*
* Release underlying C context.
 */
func (obj *Verifier) Delete() {
	if obj == nil {
		return
	}
	runtime.SetFinalizer(obj, nil)
	obj.delete()
}

/*
* Release underlying C context.
 */
func (obj *Verifier) delete() {
	C.vscf_verifier_delete(obj.cCtx)
}

/*
* Start verifying a signature.
 */
func (obj *Verifier) Reset(signature []byte) error {
	signatureData := helperWrapData(signature)

	proxyResult := /*pr4*/ C.vscf_verifier_reset(obj.cCtx, signatureData)

	err := FoundationErrorHandleStatus(proxyResult)
	if err != nil {
		return err
	}

	runtime.KeepAlive(obj)

	return nil
}

/*
* Add given data to the signed data.
 */
func (obj *Verifier) AppendData(data []byte) {
	dataData := helperWrapData(data)

	C.vscf_verifier_append_data(obj.cCtx, dataData)

	runtime.KeepAlive(obj)

	return
}

/*
* Verify accumulated data.
 */
func (obj *Verifier) Verify(publicKey PublicKey) bool {
	proxyResult := /*pr4*/ C.vscf_verifier_verify(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(publicKey.Ctx())))

	runtime.KeepAlive(obj)

	runtime.KeepAlive(publicKey)

	return bool(proxyResult) /* r9 */
}
