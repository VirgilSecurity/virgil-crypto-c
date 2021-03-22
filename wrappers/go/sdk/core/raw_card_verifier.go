package sdk_core

// #include <virgil/sdk/core/vssc_core_sdk_public.h>
import "C"
import foundation "virgil/foundation"
import unsafe "unsafe"
import "runtime"

/*
* Class responsible for verifying "raw card".
 */
type RawCardVerifier struct {
}

/*
* Verifies given "raw card" with provided signer and public key.
 */
func RawCardVerifierVerify(rawCard *RawCard, signerId string, publicKey foundation.PublicKey) bool {
	signerIdChar := C.CString(signerId)
	defer C.free(unsafe.Pointer(signerIdChar))
	signerIdStr := C.vsc_str_from_str(signerIdChar)

	proxyResult := /*pr4*/ C.vssc_raw_card_verifier_verify((*C.vssc_raw_card_t)(unsafe.Pointer(rawCard.Ctx())), signerIdStr, (*C.vscf_impl_t)(unsafe.Pointer(publicKey.Ctx())))

	runtime.KeepAlive(rawCard)

	runtime.KeepAlive(signerId)

	runtime.KeepAlive(publicKey)

	return bool(proxyResult) /* r9 */
}

/*
* Verifies self-signature.
 */
func RawCardVerifierVerifySelf(rawCard *RawCard, publicKey foundation.PublicKey) bool {
	proxyResult := /*pr4*/ C.vssc_raw_card_verifier_verify_self((*C.vssc_raw_card_t)(unsafe.Pointer(rawCard.Ctx())), (*C.vscf_impl_t)(unsafe.Pointer(publicKey.Ctx())))

	runtime.KeepAlive(rawCard)

	runtime.KeepAlive(publicKey)

	return bool(proxyResult) /* r9 */
}

/*
* Verifies signature of Virgil Cards Service.
 */
func RawCardVerifierVerifyVirgil(rawCard *RawCard, publicKey foundation.PublicKey) bool {
	proxyResult := /*pr4*/ C.vssc_raw_card_verifier_verify_virgil((*C.vssc_raw_card_t)(unsafe.Pointer(rawCard.Ctx())), (*C.vscf_impl_t)(unsafe.Pointer(publicKey.Ctx())))

	runtime.KeepAlive(rawCard)

	runtime.KeepAlive(publicKey)

	return bool(proxyResult) /* r9 */
}
