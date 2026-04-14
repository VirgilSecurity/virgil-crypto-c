#define VSCP_HANDLE_STATUS(status) do { if(status != vscp_status_SUCCESS) { vscp_handle_throw_exception(status); } } while (false)

zend_class_entry* vscp_exception_ce;

void
vscp_handle_throw_exception(vscp_status_t status) {

    switch(status) {

    case vscp_status_SUCCESS:
        break;
    case vscp_status_ERROR_BAD_ARGUMENTS:
        zend_throw_exception_ex(vscp_exception_ce, -1, "This error should not be returned if assertions is enabled.");
        break;
    case vscp_status_ERROR_PYTHIA_INNER_FAIL:
        zend_throw_exception_ex(vscp_exception_ce, -200, "Underlying pythia library returns -1.");
        break;
    case vscp_status_ERROR_RNG_FAILED:
        zend_throw_exception_ex(vscp_exception_ce, -202, "Underlying random number generator failed.");
        break;
    }
}
