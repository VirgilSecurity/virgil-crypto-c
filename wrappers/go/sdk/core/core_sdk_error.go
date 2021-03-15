package sdk_core

// #include <virgil/sdk/core/vssc_core_sdk_public.h>
import "C"
import "fmt"


/*
* Defines the library status codes.
*/
type CoreSdkError struct {
    Code int
    Message string
}
const (
    /*
    * Met internal inconsistency.
    */
    CoreSdkErrorInternalError int = -1
    /*
    * Generic error for any find operation.
    */
    CoreSdkErrorNotFound int = -100
    /*
    * Failed to decode Base64URL string.
    */
    CoreSdkErrorDecodeBase64UrlFailed int = -101
    /*
    * Failed to initialize random module.
    */
    CoreSdkErrorInitRandomFailed int = -102
    /*
    * Failed to export public key, underlying crypto returned an error.
    */
    CoreSdkErrorExportPublicKeyFailed int = -103
    /*
    * Failed to import public key, underlying crypto returned an error.
    */
    CoreSdkErrorImportPublicKeyFailed int = -104
    /*
    * Failed to produce signature, underlying crypto returned an error.
    */
    CoreSdkErrorProduceSignatureFailed int = -105
    /*
    * Failed to produce public key id.
    */
    CoreSdkErrorProducePublicKeyIdFailed int = -106
    /*
    * Failed to parse JWT.
    */
    CoreSdkErrorParseJwtFailed int = -201
    /*
    * Failed to produce JWT signature.
    */
    CoreSdkErrorSignJwtFailed int = -202
    /*
    * Requested value is not found within JSON object.
    */
    CoreSdkErrorJsonValueNotFound int = -203
    /*
    * Actual JSON value type differs from the requested.
    */
    CoreSdkErrorJsonValueTypeMismatch int = -204
    /*
    * Requested JSON binary value is not base64 encoded.
    */
    CoreSdkErrorJsonValueIsNotBase64 int = -205
    /*
    * Parse JSON string failed.
    */
    CoreSdkErrorParseJsonFailed int = -206
    /*
    * Failed to send HTTP request.
    */
    CoreSdkErrorHttpSendRequestFailed int = -301
    /*
    * Got invalid HTTP status code.
    */
    CoreSdkErrorHttpStatusCodeInvalid int = -302
    /*
    * Failed to parse HTTP body.
    */
    CoreSdkErrorHttpBodyParseFailed int = -303
    /*
    * Cannot find HTTP header with a given name.
    */
    CoreSdkErrorHttpHeaderNotFound int = -304
    /*
    * Failed to parse HTTP URL.
    */
    CoreSdkErrorHttpUrlInvalidFormat int = -305
    /*
    * Response processing failed because given HTTP Response contains Virgil Service error.
    */
    CoreSdkErrorHttpResponseContainsServiceError int = -401
    /*
    * Given HTTP response body can not be parsed in an expected way.
    */
    CoreSdkErrorHttpResponseBodyParseFailed int = -402
    /*
    * Failed to parse card content.
    */
    CoreSdkErrorRawCardContentParseFailed int = -501
    /*
    * Failed to parse card signature.
    */
    CoreSdkErrorRawCardSignatureParseFailed int = -502
    /*
    * Failed to verify one of the Raw Card signatures.
    */
    CoreSdkErrorRawCardSignatureVerificationFailed int = -503
    /*
    * Failed to parse card, found card's version is not supported.
    */
    CoreSdkErrorCardVersionIsNotSupported int = -504
    /*
    * The Card returned by Virgil Cards Service is not what was requested.
    */
    CoreSdkErrorServiceReturnedInvalidCard int = -505
)

func (obj *CoreSdkError) Error() string {
    return fmt.Sprintf("CoreSdkError{code: %v message: %s}", obj.Code, obj.Message)
}

/* Check given C status, and if it's not "success" then raise correspond error. */
func CoreSdkErrorHandleStatus(status C.vssc_status_t) error {
    if status != C.vssc_status_SUCCESS {
        switch (status) {
        case C.vssc_status_INTERNAL_ERROR:
            return &CoreSdkError {int(status), "Met internal inconsistency."}
        case C.vssc_status_NOT_FOUND:
            return &CoreSdkError {int(status), "Generic error for any find operation."}
        case C.vssc_status_DECODE_BASE64_URL_FAILED:
            return &CoreSdkError {int(status), "Failed to decode Base64URL string."}
        case C.vssc_status_INIT_RANDOM_FAILED:
            return &CoreSdkError {int(status), "Failed to initialize random module."}
        case C.vssc_status_EXPORT_PUBLIC_KEY_FAILED:
            return &CoreSdkError {int(status), "Failed to export public key, underlying crypto returned an error."}
        case C.vssc_status_IMPORT_PUBLIC_KEY_FAILED:
            return &CoreSdkError {int(status), "Failed to import public key, underlying crypto returned an error."}
        case C.vssc_status_PRODUCE_SIGNATURE_FAILED:
            return &CoreSdkError {int(status), "Failed to produce signature, underlying crypto returned an error."}
        case C.vssc_status_PRODUCE_PUBLIC_KEY_ID_FAILED:
            return &CoreSdkError {int(status), "Failed to produce public key id."}
        case C.vssc_status_PARSE_JWT_FAILED:
            return &CoreSdkError {int(status), "Failed to parse JWT."}
        case C.vssc_status_SIGN_JWT_FAILED:
            return &CoreSdkError {int(status), "Failed to produce JWT signature."}
        case C.vssc_status_JSON_VALUE_NOT_FOUND:
            return &CoreSdkError {int(status), "Requested value is not found within JSON object."}
        case C.vssc_status_JSON_VALUE_TYPE_MISMATCH:
            return &CoreSdkError {int(status), "Actual JSON value type differs from the requested."}
        case C.vssc_status_JSON_VALUE_IS_NOT_BASE64:
            return &CoreSdkError {int(status), "Requested JSON binary value is not base64 encoded."}
        case C.vssc_status_PARSE_JSON_FAILED:
            return &CoreSdkError {int(status), "Parse JSON string failed."}
        case C.vssc_status_HTTP_SEND_REQUEST_FAILED:
            return &CoreSdkError {int(status), "Failed to send HTTP request."}
        case C.vssc_status_HTTP_STATUS_CODE_INVALID:
            return &CoreSdkError {int(status), "Got invalid HTTP status code."}
        case C.vssc_status_HTTP_BODY_PARSE_FAILED:
            return &CoreSdkError {int(status), "Failed to parse HTTP body."}
        case C.vssc_status_HTTP_HEADER_NOT_FOUND:
            return &CoreSdkError {int(status), "Cannot find HTTP header with a given name."}
        case C.vssc_status_HTTP_URL_INVALID_FORMAT:
            return &CoreSdkError {int(status), "Failed to parse HTTP URL."}
        case C.vssc_status_HTTP_RESPONSE_CONTAINS_SERVICE_ERROR:
            return &CoreSdkError {int(status), "Response processing failed because given HTTP Response contains Virgil Service error."}
        case C.vssc_status_HTTP_RESPONSE_BODY_PARSE_FAILED:
            return &CoreSdkError {int(status), "Given HTTP response body can not be parsed in an expected way."}
        case C.vssc_status_RAW_CARD_CONTENT_PARSE_FAILED:
            return &CoreSdkError {int(status), "Failed to parse card content."}
        case C.vssc_status_RAW_CARD_SIGNATURE_PARSE_FAILED:
            return &CoreSdkError {int(status), "Failed to parse card signature."}
        case C.vssc_status_RAW_CARD_SIGNATURE_VERIFICATION_FAILED:
            return &CoreSdkError {int(status), "Failed to verify one of the Raw Card signatures."}
        case C.vssc_status_CARD_VERSION_IS_NOT_SUPPORTED:
            return &CoreSdkError {int(status), "Failed to parse card, found card's version is not supported."}
        case C.vssc_status_SERVICE_RETURNED_INVALID_CARD:
            return &CoreSdkError {int(status), "The Card returned by Virgil Cards Service is not what was requested."}
        }
    }
    return nil
}

type wrapError struct {
    err error
    msg string
}

func (obj *wrapError) Error() string {
    return fmt.Sprintf("%s: %v", obj.msg, obj.err)
}

func (obj *wrapError) Unwrap() error {
    return obj.err
}
