#define VSCE_HANDLE_STATUS(status) do { if(status != vsce_status_SUCCESS) { vsce_handle_throw_exception(status); } } while (false)

zend_class_entry* vsce_exception_ce;

void
vsce_handle_throw_exception(vsce_status_t status) {

    switch(status) {

    case vsce_status_SUCCESS:
        break;
    case vsce_status_ERROR_INVALID_SUCCESS_PROOF:
        zend_throw_exception_ex(vsce_exception_ce, -1, "Success proof check failed.");
        break;
    case vsce_status_ERROR_INVALID_FAIL_PROOF:
        zend_throw_exception_ex(vsce_exception_ce, -2, "Failure proof check failed.");
        break;
    case vsce_status_ERROR_RNG_FAILED:
        zend_throw_exception_ex(vsce_exception_ce, -3, "RNG returned error.");
        break;
    case vsce_status_ERROR_PROTOBUF_DECODE_FAILED:
        zend_throw_exception_ex(vsce_exception_ce, -4, "Protobuf decode failed.");
        break;
    case vsce_status_ERROR_INVALID_PUBLIC_KEY:
        zend_throw_exception_ex(vsce_exception_ce, -5, "Invalid public key.");
        break;
    case vsce_status_ERROR_INVALID_PRIVATE_KEY:
        zend_throw_exception_ex(vsce_exception_ce, -6, "Invalid private key.");
        break;
    case vsce_status_ERROR_AES_FAILED:
        zend_throw_exception_ex(vsce_exception_ce, -7, "AES error occurred.");
        break;
    }
}
