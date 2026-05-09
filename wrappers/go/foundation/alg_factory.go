package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Create algorithms based on the given information.
*/
type AlgFactory struct {
}

/*
* Create algorithm that implements "hash stream" interface.
*/
func AlgFactoryCreateHashFromInfo(algInfo AlgInfo) (Hash, error) {
    proxyResult := C.vscf_alg_factory_create_hash_from_info((*C.vscf_impl_t)(unsafe.Pointer(algInfo.Ctx())))

    runtime.KeepAlive(algInfo)

    return FoundationImplementationWrapHash(proxyResult)
}

/*
* Create algorithm that implements "mac stream" interface.
*/
func AlgFactoryCreateMacFromInfo(algInfo AlgInfo) (Mac, error) {
    proxyResult := C.vscf_alg_factory_create_mac_from_info((*C.vscf_impl_t)(unsafe.Pointer(algInfo.Ctx())))

    runtime.KeepAlive(algInfo)

    return FoundationImplementationWrapMac(proxyResult)
}

/*
* Create algorithm that implements "kdf" interface.
*/
func AlgFactoryCreateKdfFromInfo(algInfo AlgInfo) (Kdf, error) {
    proxyResult := C.vscf_alg_factory_create_kdf_from_info((*C.vscf_impl_t)(unsafe.Pointer(algInfo.Ctx())))

    runtime.KeepAlive(algInfo)

    return FoundationImplementationWrapKdf(proxyResult)
}

/*
* Create algorithm that implements "salted kdf" interface.
*/
func AlgFactoryCreateSaltedKdfFromInfo(algInfo AlgInfo) (SaltedKdf, error) {
    proxyResult := C.vscf_alg_factory_create_salted_kdf_from_info((*C.vscf_impl_t)(unsafe.Pointer(algInfo.Ctx())))

    runtime.KeepAlive(algInfo)

    return FoundationImplementationWrapSaltedKdf(proxyResult)
}

/*
* Create algorithm that implements "cipher" interface.
*/
func AlgFactoryCreateCipherFromInfo(algInfo AlgInfo) (Cipher, error) {
    proxyResult := C.vscf_alg_factory_create_cipher_from_info((*C.vscf_impl_t)(unsafe.Pointer(algInfo.Ctx())))

    runtime.KeepAlive(algInfo)

    return FoundationImplementationWrapCipher(proxyResult)
}

/*
* Create algorithm that implements "padding" interface.
*/
func AlgFactoryCreatePaddingFromInfo(algInfo AlgInfo, random Random) (Padding, error) {
    proxyResult := C.vscf_alg_factory_create_padding_from_info((*C.vscf_impl_t)(unsafe.Pointer(algInfo.Ctx())), (*C.vscf_impl_t)(unsafe.Pointer(random.Ctx())))

    runtime.KeepAlive(algInfo)

    runtime.KeepAlive(random)

    return FoundationImplementationWrapPadding(proxyResult)
}
