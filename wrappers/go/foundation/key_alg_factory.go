package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_common
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_foundation
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"

/*
* Create a bridge between "raw keys" and algorithms that can import them.
*/
type KeyAlgFactory struct {
}

/*
* Create a key algorithm based on an identifier.
*/
func KeyAlgFactoryCreateFromAlgId (algId AlgId, random IRandom) IKeyAlg {
    error := C.vscf_error_t()
    C.vscf_error_reset(&error)

    proxyResult := C.vscf_key_alg_factory_create_from_alg_id(algId /*pa7*/, random.Ctx(), &error)

    FoundationErrorHandleStatus(error.status)

    return FoundationImplementationWrapIKeyAlg(proxyResult) /* r4 */
}

/*
* Create a key algorithm correspond to a specific key.
*/
func KeyAlgFactoryCreateFromKey (key IKey, random IRandom) IKeyAlg {
    error := C.vscf_error_t()
    C.vscf_error_reset(&error)

    proxyResult := C.vscf_key_alg_factory_create_from_key(key.Ctx(), random.Ctx(), &error)

    FoundationErrorHandleStatus(error.status)

    return FoundationImplementationWrapIKeyAlg(proxyResult) /* r4 */
}

/*
* Create a key algorithm that can import "raw public key".
*/
func KeyAlgFactoryCreateFromRawPublicKey (publicKey RawPublicKey, random IRandom) IKeyAlg {
    error := C.vscf_error_t()
    C.vscf_error_reset(&error)

    proxyResult := C.vscf_key_alg_factory_create_from_raw_public_key(publicKey.Ctx(), random.Ctx(), &error)

    FoundationErrorHandleStatus(error.status)

    return FoundationImplementationWrapIKeyAlg(proxyResult) /* r4 */
}

/*
* Create a key algorithm that can import "raw private key".
*/
func KeyAlgFactoryCreateFromRawPrivateKey (privateKey RawPrivateKey, random IRandom) IKeyAlg {
    error := C.vscf_error_t()
    C.vscf_error_reset(&error)

    proxyResult := C.vscf_key_alg_factory_create_from_raw_private_key(privateKey.Ctx(), random.Ctx(), &error)

    FoundationErrorHandleStatus(error.status)

    return FoundationImplementationWrapIKeyAlg(proxyResult) /* r4 */
}
