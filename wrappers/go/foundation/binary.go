package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Contains utils for convertion from bytes to HEX and vice-versa.
*/
type Binary struct {
}

/*
* Return buffer length enaugh to hold hexed data.
*/
func BinaryToHexLen(dataLen uint) uint {
    proxyResult := /*pr4*/C.vscf_binary_to_hex_len((C.size_t)(dataLen)/*pa10*/)

    return uint(proxyResult) /* r9 */
}

/*
* Converts byte array to hex.
* Output length should be twice bigger then input.
*/
func BinaryToHex(data []byte) string {
    hexStrBuf := C.vsc_str_buffer_new_with_capacity((C.size_t)(BinaryToHexLen(uint(len(data))) /* lg1 */))
    defer C.vsc_str_buffer_delete(hexStrBuf)
    dataData := helperWrapData (data)

    C.vscf_binary_to_hex(dataData, hexStrBuf)

    return C.GoString(C.vsc_str_buffer_chars(hexStrBuf)) /* r7.1 */
}

/*
* Return buffer length enaugh to hold unhexed data.
*/
func BinaryFromHexLen(hexLen uint) uint {
    proxyResult := /*pr4*/C.vscf_binary_from_hex_len((C.size_t)(hexLen)/*pa10*/)

    return uint(proxyResult) /* r9 */
}

/*
* Converts hex string to byte array.
* Output length should be at least half of the input hex string.
*/
func BinaryFromHex(hexStr string) ([]byte, error) {
    hexStrChar := C.CString(hexStr)
    defer C.free(unsafe.Pointer(hexStrChar))
    hexStrStr := C.vsc_str_from_str(hexStrChar)

    dataBuf, dataBufErr := newBuffer(int(BinaryFromHexLen(uint(len(hexStr))) /* lg1 */))
    if dataBufErr != nil {
        return nil, dataBufErr
    }
    defer dataBuf.delete()


    proxyResult := /*pr4*/C.vscf_binary_from_hex(hexStrStr, dataBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(hexStr)

    return dataBuf.getData() /* r7 */, nil
}
