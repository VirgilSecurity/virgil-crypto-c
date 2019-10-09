#define VSCE_HANDLE_STATUS(status) do { if(status != vsce_status_SUCCESS) { vsce_handle_throw_exception(status); goto fail; } } while (false)

void
vsce_handle_throw_exception(vsce_status_t status) {
    switch(status) {

    case vsce_status_ERROR_INVALID_SUCCESS_PROOF:
        zend_throw_exception(NULL, "VSCE: Success proof check failed.", -1);
        break;
    case vsce_status_ERROR_INVALID_FAIL_PROOF:
        zend_throw_exception(NULL, "VSCE: Failure proof check failed.", -2);
        break;
    case vsce_status_ERROR_RNG_FAILED:
        zend_throw_exception(NULL, "VSCE: RNG returned error.", -3);
        break;
    case vsce_status_ERROR_PROTOBUF_DECODE_FAILED:
        zend_throw_exception(NULL, "VSCE: Protobuf decode failed.", -4);
        break;
    case vsce_status_ERROR_INVALID_PUBLIC_KEY:
        zend_throw_exception(NULL, "VSCE: Invalid public key.", -5);
        break;
    case vsce_status_ERROR_INVALID_PRIVATE_KEY:
        zend_throw_exception(NULL, "VSCE: Invalid private key.", -6);
        break;
    case vsce_status_ERROR_AES_FAILED:
        zend_throw_exception(NULL, "VSCE: AES error occurred.", -7);
        break;
    }
}
