package foundation

// #cgo CFLAGS: -I${SRCDIR}/../../../build/library/foundation/include/virgil/crypto/foundation
// #cgo CFLAGS: -I${SRCDIR}/../../../library/foundation/include/virgil/crypto/foundation
// #cgo LDFLAGS: -L${SRCDIR}/../../java/binaries/linux/lib -lvscf_foundation_java
// #include <vscf_foundation_public.h>
import "C"
import . "virgil/common"

/*
* Simple PEM wrapper.
*/
type Pem struct {
}

/*
* Return length in bytes required to hold wrapped PEM format.
*/
func PemWrappedLen (title string, dataLen int32) int32 {
    proxyResult := C.vscf_pem_wrapped_len(title, dataLen)

    return proxyResult //r9
}

/*
* Takes binary data and wraps it to the simple PEM format - no
* additional information just header-base64-footer.
* Note, written buffer is NOT null-terminated.
*/
func PemWrap (title string, data []byte) []byte {
    pemCount := PemWrappedLen(title, int32(len(data))) /* lg1 */
    pemBuf := NewBuffer(pemCount)
    defer pemBuf.Clear()


    C.vscf_pem_wrap(title, WrapData(data), pemBuf)

    return pemBuf.GetData() /* r7 */
}

/*
* Return length in bytes required to hold unwrapped binary.
*/
func PemUnwrappedLen (pemLen int32) int32 {
    proxyResult := C.vscf_pem_unwrapped_len(pemLen)

    return proxyResult //r9
}

/*
* Takes PEM data and extract binary data from it.
*/
func PemUnwrap (pem []byte) []byte {
    dataCount := PemUnwrappedLen(int32(len(pem))) /* lg1 */
    dataBuf := NewBuffer(dataCount)
    defer dataBuf.Clear()


    proxyResult := C.vscf_pem_unwrap(WrapData(pem), dataBuf)

    FoundationErrorHandleStatus(proxyResult)

    return dataBuf.GetData() /* r7 */
}

/*
* Returns PEM title if PEM data is valid, otherwise - empty data.
*/
func PemTitle (pem []byte) []byte {
    proxyResult := C.vscf_pem_title(WrapData(pem))

    return ExtractData(proxyResult) /* r1 */
}
