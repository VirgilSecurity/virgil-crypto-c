package foundation

// #cgo CFLAGS: -I${SRCDIR}/../../../build/library/foundation/include/virgil/crypto/foundation
// #cgo CFLAGS: -I${SRCDIR}/../../../library/foundation/include/virgil/crypto/foundation
// #cgo LDFLAGS: -L${SRCDIR}/../../java/binaries/linux/lib -lvscf_foundation_java
// #include <vscf_foundation_public.h>
import "C"

/*
* Create algorithms based on the given information.
*/
type AlgFactory struct {
}

/*
* Create algorithm that implements "hash stream" interface.
*/
func AlgFactoryCreateHashFromInfo (algInfo IAlgInfo) IHash {
    proxyResult := C.vscf_alg_factory_create_hash_from_info(algInfo.Ctx())

    return FoundationImplementationWrapIHash(proxyResult) /* r4 */
}

/*
* Create algorithm that implements "mac stream" interface.
*/
func AlgFactoryCreateMacFromInfo (algInfo IAlgInfo) IMac {
    proxyResult := C.vscf_alg_factory_create_mac_from_info(algInfo.Ctx())

    return FoundationImplementationWrapIMac(proxyResult) /* r4 */
}

/*
* Create algorithm that implements "kdf" interface.
*/
func AlgFactoryCreateKdfFromInfo (algInfo IAlgInfo) IKdf {
    proxyResult := C.vscf_alg_factory_create_kdf_from_info(algInfo.Ctx())

    return FoundationImplementationWrapIKdf(proxyResult) /* r4 */
}

/*
* Create algorithm that implements "salted kdf" interface.
*/
func AlgFactoryCreateSaltedKdfFromInfo (algInfo IAlgInfo) ISaltedKdf {
    proxyResult := C.vscf_alg_factory_create_salted_kdf_from_info(algInfo.Ctx())

    return FoundationImplementationWrapISaltedKdf(proxyResult) /* r4 */
}

/*
* Create algorithm that implements "cipher" interface.
*/
func AlgFactoryCreateCipherFromInfo (algInfo IAlgInfo) ICipher {
    proxyResult := C.vscf_alg_factory_create_cipher_from_info(algInfo.Ctx())

    return FoundationImplementationWrapICipher(proxyResult) /* r4 */
}
