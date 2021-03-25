package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import "runtime"
import unsafe "unsafe"


/*
* Create algorithms based on the given information.
*/
type AlgFactory struct {
}

/*
* Create algorithm that implements "hash stream" interface.
*/
func AlgFactoryCreateHashFromInfo(algInfo AlgInfo) (Hash, error) {
    proxyResult := /*pr4*/C.vscf_alg_factory_create_hash_from_info((*C.vscf_impl_t)(unsafe.Pointer(algInfo.Ctx())))

    runtime.KeepAlive(algInfo)

    return ImplementationWrapHash(unsafe.Pointer(proxyResult)) /* r4 */
}

/*
* Create algorithm that implements "mac stream" interface.
*/
func AlgFactoryCreateMacFromInfo(algInfo AlgInfo) (Mac, error) {
    proxyResult := /*pr4*/C.vscf_alg_factory_create_mac_from_info((*C.vscf_impl_t)(unsafe.Pointer(algInfo.Ctx())))

    runtime.KeepAlive(algInfo)

    return ImplementationWrapMac(unsafe.Pointer(proxyResult)) /* r4 */
}

/*
* Create algorithm that implements "kdf" interface.
*/
func AlgFactoryCreateKdfFromInfo(algInfo AlgInfo) (Kdf, error) {
    proxyResult := /*pr4*/C.vscf_alg_factory_create_kdf_from_info((*C.vscf_impl_t)(unsafe.Pointer(algInfo.Ctx())))

    runtime.KeepAlive(algInfo)

    return ImplementationWrapKdf(unsafe.Pointer(proxyResult)) /* r4 */
}

/*
* Create algorithm that implements "salted kdf" interface.
*/
func AlgFactoryCreateSaltedKdfFromInfo(algInfo AlgInfo) (SaltedKdf, error) {
    proxyResult := /*pr4*/C.vscf_alg_factory_create_salted_kdf_from_info((*C.vscf_impl_t)(unsafe.Pointer(algInfo.Ctx())))

    runtime.KeepAlive(algInfo)

    return ImplementationWrapSaltedKdf(unsafe.Pointer(proxyResult)) /* r4 */
}

/*
* Create algorithm that implements "cipher" interface.
*/
func AlgFactoryCreateCipherFromInfo(algInfo AlgInfo) (Cipher, error) {
    proxyResult := /*pr4*/C.vscf_alg_factory_create_cipher_from_info((*C.vscf_impl_t)(unsafe.Pointer(algInfo.Ctx())))

    runtime.KeepAlive(algInfo)

    return ImplementationWrapCipher(unsafe.Pointer(proxyResult)) /* r4 */
}

/*
* Create algorithm that implements "padding" interface.
*/
func AlgFactoryCreatePaddingFromInfo(algInfo AlgInfo, random Random) (Padding, error) {
    proxyResult := /*pr4*/C.vscf_alg_factory_create_padding_from_info((*C.vscf_impl_t)(unsafe.Pointer(algInfo.Ctx())), (*C.vscf_impl_t)(unsafe.Pointer(random.Ctx())))

    runtime.KeepAlive(algInfo)

    runtime.KeepAlive(random)

    return ImplementationWrapPadding(unsafe.Pointer(proxyResult)) /* r4 */
}
