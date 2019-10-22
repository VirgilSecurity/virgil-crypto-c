package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_common
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_foundation
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import . "virgil/common"

/*
* Provide conversion logic between OID and algorithm tags.
*/
type Oid struct {
}

/*
* Return OID for given algorithm identifier.
*/
func OidFromAlgId (algId AlgId) []byte {
    proxyResult := C.vscf_oid_from_alg_id(algId /*pa7*/)

    return ExtractData(proxyResult) /* r1 */
}

/*
* Return algorithm identifier for given OID.
*/
func OidToAlgId (oid []byte) AlgId {
    proxyResult := C.vscf_oid_to_alg_id(WrapData(oid))

    return AlgId(proxyResult) /* r8 */
}

/*
* Return OID for a given identifier.
*/
func OidFromId (oidId OidId) []byte {
    proxyResult := C.vscf_oid_from_id(oidId /*pa7*/)

    return ExtractData(proxyResult) /* r1 */
}

/*
* Return identifier for a given OID.
*/
func OidToId (oid []byte) OidId {
    proxyResult := C.vscf_oid_to_id(WrapData(oid))

    return OidId(proxyResult) /* r8 */
}

/*
* Map oid identifier to the algorithm identifier.
*/
func OidIdToAlgId (oidId OidId) AlgId {
    proxyResult := C.vscf_oid_id_to_alg_id(oidId /*pa7*/)

    return AlgId(proxyResult) /* r8 */
}

/*
* Return true if given OIDs are equal.
*/
func OidEqual (lhs []byte, rhs []byte) bool {
    proxyResult := C.vscf_oid_equal(WrapData(lhs), WrapData(rhs))

    return proxyResult //r9
}
