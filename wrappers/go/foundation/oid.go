package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
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
func OidFromAlgId (algId AlgId) []byte {
    proxyResult := /*pr4*/C.vscf_oid_from_alg_id(C.vscf_alg_id_t(algId) /*pa7*/)

    return helperDataToBytes(proxyResult) /* r1 */
}

/*
* Return algorithm identifier for given OID.
*/
func OidToAlgId (oid []byte) AlgId {
    oidData := C.vsc_data((*C.uint8_t)(&oid[0]), C.size_t(len(oid)))

    proxyResult := /*pr4*/C.vscf_oid_to_alg_id(oidData)

    return AlgId(proxyResult) /* r8 */
}

/*
* Return OID for a given identifier.
*/
func OidFromId (oidId OidId) []byte {
    proxyResult := /*pr4*/C.vscf_oid_from_id(C.vscf_oid_id_t(oidId) /*pa7*/)

    return helperDataToBytes(proxyResult) /* r1 */
}

/*
* Return identifier for a given OID.
*/
func OidToId (oid []byte) OidId {
    oidData := C.vsc_data((*C.uint8_t)(&oid[0]), C.size_t(len(oid)))

    proxyResult := /*pr4*/C.vscf_oid_to_id(oidData)

    return OidId(proxyResult) /* r8 */
}

/*
* Map oid identifier to the algorithm identifier.
*/
func OidIdToAlgId (oidId OidId) AlgId {
    proxyResult := /*pr4*/C.vscf_oid_id_to_alg_id(C.vscf_oid_id_t(oidId) /*pa7*/)

    return AlgId(proxyResult) /* r8 */
}

/*
* Return true if given OIDs are equal.
*/
func OidEqual (lhs []byte, rhs []byte) bool {
    lhsData := C.vsc_data((*C.uint8_t)(&lhs[0]), C.size_t(len(lhs)))
    rhsData := C.vsc_data((*C.uint8_t)(&rhs[0]), C.size_t(len(rhs)))

    proxyResult := /*pr4*/C.vscf_oid_equal(lhsData, rhsData)

    return bool(proxyResult) /* r9 */
}
