package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"


/*
* Create algorithms based on the given information.
*/
type AlgFactory struct {
}

/*
* Create algorithm that implements "hash stream" interface.
*/
func AlgFactoryCreateHashFromInfo (algInfo IAlgInfo) (IHash, error) {
    proxyResult := /*pr4*/C.vscf_alg_factory_create_hash_from_info((*C.vscf_impl_t)(algInfo.ctx()))

    return FoundationImplementationWrapIHash(proxyResult) /* r4 */
}

/*
* Create algorithm that implements "mac stream" interface.
*/
func AlgFactoryCreateMacFromInfo (algInfo IAlgInfo) (IMac, error) {
    proxyResult := /*pr4*/C.vscf_alg_factory_create_mac_from_info((*C.vscf_impl_t)(algInfo.ctx()))

    return FoundationImplementationWrapIMac(proxyResult) /* r4 */
}

/*
* Create algorithm that implements "kdf" interface.
*/
func AlgFactoryCreateKdfFromInfo (algInfo IAlgInfo) (IKdf, error) {
    proxyResult := /*pr4*/C.vscf_alg_factory_create_kdf_from_info((*C.vscf_impl_t)(algInfo.ctx()))

    return FoundationImplementationWrapIKdf(proxyResult) /* r4 */
}

/*
* Create algorithm that implements "salted kdf" interface.
*/
func AlgFactoryCreateSaltedKdfFromInfo (algInfo IAlgInfo) (ISaltedKdf, error) {
    proxyResult := /*pr4*/C.vscf_alg_factory_create_salted_kdf_from_info((*C.vscf_impl_t)(algInfo.ctx()))

    return FoundationImplementationWrapISaltedKdf(proxyResult) /* r4 */
}

/*
* Create algorithm that implements "cipher" interface.
*/
func AlgFactoryCreateCipherFromInfo (algInfo IAlgInfo) (ICipher, error) {
    proxyResult := /*pr4*/C.vscf_alg_factory_create_cipher_from_info((*C.vscf_impl_t)(algInfo.ctx()))

    return FoundationImplementationWrapICipher(proxyResult) /* r4 */
}
