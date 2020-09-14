#ifndef VSSC_HTTP_CLIENT_X_IMPL_H_INCLUDED
#define VSSC_HTTP_CLIENT_X_IMPL_H_INCLUDED

#include "vssc_library.h"
#include "vssc_http_request.h"
#include "vssc_http_response.h"


typedef struct vssc_http_client_x_impl_t vssc_http_client_x_impl_t;

VSSC_PRIVATE vssc_http_client_x_impl_t *
vssc_http_client_x_impl_new();

VSSC_PRIVATE void
vssc_http_client_x_impl_delete(vssc_http_client_x_impl_t *self);

VSSC_PRIVATE vssc_http_response_t *
vssc_http_client_x_impl_send(
        vssc_http_client_x_impl_t *self, const vssc_http_request_t *http_request, vssc_error_t *error);


VSSC_PRIVATE vssc_http_response_t *
vssc_http_client_x_auth_impl_send(vssc_http_client_x_impl_t *self, const vssc_http_request_t *http_request,
        vsc_str_t auth_type, vsc_str_t auth_credentials, vssc_error_t *error);

#endif // VSSC_HTTP_CLIENT_X_IMPL_H_INCLUDED
