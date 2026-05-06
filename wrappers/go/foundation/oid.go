package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"


/*
* Provide conversion logic between OID and algorithm tags.
*/
type Oid struct {
}

/*
* Return OID for given algorithm identifier.
*/
func OidFromAlgId(algId AlgId) []byte {
    proxyResult := /*pr4*/C.vscf_oid_from_alg_id(C.vscf_alg_id_t(algId) /*pa7*/)

    return helperExtractData(proxyResult) /* r1 */
}

/*
* Return algorithm identifier for given OID.
*/
func OidToAlgId(oid []byte) AlgId {
    oidData := helperWrapData (oid)

    proxyResult := /*pr4*/C.vscf_oid_to_alg_id(oidData)

    return AlgId(proxyResult) /* r8 */
}

/*
* Return OID for a given identifier.
*/
func OidFromId(oidId OidId) []byte {
    proxyResult := /*pr4*/C.vscf_oid_from_id(C.vscf_oid_id_t(oidId) /*pa7*/)

    return helperExtractData(proxyResult) /* r1 */
}

/*
* Return identifier for a given OID.
*/
func OidToId(oid []byte) OidId {
    oidData := helperWrapData (oid)

    proxyResult := /*pr4*/C.vscf_oid_to_id(oidData)

    return OidId(proxyResult) /* r8 */
}

/*
* Map oid identifier to the algorithm identifier.
*/
func OidIdToAlgId(oidId OidId) AlgId {
    proxyResult := /*pr4*/C.vscf_oid_id_to_alg_id(C.vscf_oid_id_t(oidId) /*pa7*/)

    return AlgId(proxyResult) /* r8 */
}

/*
* Return true if given OIDs are equal.
*/
func OidEqual(lhs []byte, rhs []byte) bool {
    lhsData := helperWrapData (lhs)
    rhsData := helperWrapData (rhs)

    proxyResult := /*pr4*/C.vscf_oid_equal(lhsData, rhsData)

    return bool(proxyResult) /* r9 */
}
