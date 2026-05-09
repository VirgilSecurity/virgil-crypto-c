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
    proxyResult := C.vscf_oid_from_alg_id(C.vscf_alg_id_t(algId))

    return helperExtractData(proxyResult)
}

/*
* Return algorithm identifier for given OID.
*/
func OidToAlgId(oid []byte) AlgId {
    oidData := helperWrapData (oid)

    proxyResult := C.vscf_oid_to_alg_id(oidData)

    return AlgId(proxyResult)
}

/*
* Return OID for a given identifier.
*/
func OidFromId(oidId OidId) []byte {
    proxyResult := C.vscf_oid_from_id(C.vscf_oid_id_t(oidId))

    return helperExtractData(proxyResult)
}

/*
* Return identifier for a given OID.
*/
func OidToId(oid []byte) OidId {
    oidData := helperWrapData (oid)

    proxyResult := C.vscf_oid_to_id(oidData)

    return OidId(proxyResult)
}

/*
* Map oid identifier to the algorithm identifier.
*/
func OidIdToAlgId(oidId OidId) AlgId {
    proxyResult := C.vscf_oid_id_to_alg_id(C.vscf_oid_id_t(oidId))

    return AlgId(proxyResult)
}

/*
* Return true if given OIDs are equal.
*/
func OidEqual(lhs []byte, rhs []byte) bool {
    lhsData := helperWrapData (lhs)
    rhsData := helperWrapData (rhs)

    proxyResult := C.vscf_oid_equal(lhsData, rhsData)

    return bool(proxyResult)
}
