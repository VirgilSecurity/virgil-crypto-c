package sdk_comm_kit

// #include <virgil/sdk/comm-kit/vssq_comm_kit_public.h>
import "C"
import "fmt"

/*
* Defines the library status codes.
 */
type CommKitError struct {
	Code    int
	Message string
}

const (
	/*
	 * Met internal inconsistency.
	 */
	CommKitErrorInternalError int = -1
	/*
	 * Failed to initialize RNG.
	 */
	CommKitErrorRngFailed int = -101
	/*
	 * Generic error for any find operation.
	 */
	CommKitErrorNotFound int = -102
	/*
	 * Failed to send HTTP request.
	 */
	CommKitErrorHttpSendFailed int = -103
	/*
	 * Failed to parse Ejabberd JWT.
	 */
	CommKitErrorParseEjabberdJwtFailed int = -201
	/*
	 * Failed to generate identity.
	 */
	CommKitErrorGenerateIdentityFailed int = -301
	/*
	 * Failed to generate private key.
	 */
	CommKitErrorGeneratePrivateKeyFailed int = -302
	/*
	 * Failed to import private key.
	 */
	CommKitErrorImportPrivateKeyFailed int = -303
	/*
	 * Failed to export private key.
	 */
	CommKitErrorExportPrivateKeyFailed int = -304
	/*
	 * Failed to calculate key id.
	 */
	CommKitErrorCalculateKeyIdFailed int = -305
	/*
	 * Failed to create card manager.
	 */
	CommKitErrorCreateCardManagerFailed int = -306
	/*
	 * Failed to generate card.
	 */
	CommKitErrorGenerateCardFailed int = -307
	/*
	 * Failed to generate HTTP authentication header.
	 */
	CommKitErrorGenerateAuthHeaderFailed int = -308
	/*
	 * Failed to register card because send operation failed.
	 */
	CommKitErrorRegisterCardFailedRequestFailed int = -401
	/*
	 * Failed to register card because of invalid response.
	 */
	CommKitErrorRegisterCardFailedInvalidResponse int = -402
	/*
	 * Failed to register card because response with error was returned.
	 */
	CommKitErrorRegisterCardFailedResponseWithError int = -403
	/*
	 * Failed to register card because parsing raw card failed.
	 */
	CommKitErrorRegisterCardFailedParseFailed int = -404
	/*
	 * Failed to register card because import raw card failed.
	 */
	CommKitErrorRegisterCardFailedImportFailed int = -405
	/*
	 * Failed to generate brain key because of crypto fail.
	 */
	CommKitErrorGenerateBrainkeyFailedCryptoFailed int = -501
	/*
	 * Failed to generate brain key because of RNG fail.
	 */
	CommKitErrorGenerateBrainkeyFailedRngFailed int = -502
	/*
	 * Failed to generate brain key because of blind fail.
	 */
	CommKitErrorGenerateBrainkeyFailedBlindFailed int = -503
	/*
	 * Failed to generate brain key because of deblind fail.
	 */
	CommKitErrorGenerateBrainkeyFailedDeblindFailed int = -504
	/*
	 * Failed to generate brain key because requesting hardened point from the service failed.
	 */
	CommKitErrorGenerateBrainkeyFailedHardenedPointRequestFailed int = -505
	/*
	 * Failed to generate brain key because hardened point response was returned with error.
	 */
	CommKitErrorGenerateBrainkeyFailedHardenedPointResponseWithError int = -506
	/*
	 * Failed to generate brain key because parsing hardened point response failed.
	 */
	CommKitErrorGenerateBrainkeyFailedHardenedPointParseFailed int = -507
	/*
	 * Failed to process Keyknox entry because send operation failed.
	 */
	CommKitErrorKeyknoxFailedRequestFailed int = -601
	/*
	 * Failed to process Keyknox entry because response with error was returned.
	 */
	CommKitErrorKeyknoxFailedResponseWithError int = -602
	/*
	 * Failed to process Keyknox entry because response parsing failed.
	 */
	CommKitErrorKeyknoxFailedParseResponseFailed int = -603
	/*
	 * Failed to pack Keyknox entry because export private key failed.
	 */
	CommKitErrorKeyknoxPackEntryFailedExportPrivateKeyFailed int = -604
	/*
	 * Failed to pack Keyknox entry because encrypt operation failed.
	 */
	CommKitErrorKeyknoxPackEntryFailedEncryptFailed int = -605
	/*
	 * Failed to unpack Keyknox entry because decrypt operation failed.
	 */
	CommKitErrorKeyknoxUnpackEntryFailedDecryptFailed int = -606
	/*
	 * Failed to unpack Keyknox entry because verifying signature failed.
	 */
	CommKitErrorKeyknoxUnpackEntryFailedVerifySignatureFailed int = -607
	/*
	 * Failed to unpack Keyknox entry because parse operation failed.
	 */
	CommKitErrorKeyknoxUnpackEntryFailedParseFailed int = -608
	/*
	 * Failed to unpack Keyknox entry because import private key failed.
	 */
	CommKitErrorKeyknoxUnpackEntryFailedImportPrivateKeyFailed int = -609
	/*
	 * Failed to refresh JWT because send operation failed.
	 */
	CommKitErrorRefreshJwtFailedRequestFailed int = -701
	/*
	 * Failed to refresh JWT because response with error was returned.
	 */
	CommKitErrorRefreshJwtFailedResponseWithError int = -702
	/*
	 * Failed to refresh JWT because response parsing failed.
	 */
	CommKitErrorRefreshJwtFailedParseResponseFailed int = -703
	/*
	 * Failed to refresh JWT because JWT parsing failed.
	 */
	CommKitErrorRefreshJwtFailedParseFailed int = -704
	/*
	 * Failed to reset password because send operation failed.
	 */
	CommKitErrorResetPasswordFailedRequestFailed int = -801
	/*
	 * Failed to reset password because response with error was returned.
	 */
	CommKitErrorResetPasswordFailedResponseWithError int = -802
	/*
	 * Failed to search card because a card manager initialization failed.
	 */
	CommKitErrorSearchCardFailedInitFailed int = -900
	/*
	 * Failed to search card because send operation failed.
	 */
	CommKitErrorSearchCardFailedRequestFailed int = -901
	/*
	 * Failed to search card because response with error was returned.
	 */
	CommKitErrorSearchCardFailedResponseWithError int = -902
	/*
	 * Failed to search card because required card was not found.
	 */
	CommKitErrorSearchCardFailedRequiredNotFound int = -903
	/*
	 * Failed to search card because found more then one active card.
	 */
	CommKitErrorSearchCardFailedMultipleFound int = -904
	/*
	 * Failed to search card because parsing raw card failed.
	 */
	CommKitErrorSearchCardFailedParseFailed int = -905
	/*
	 * Failed to search card because import raw card failed.
	 */
	CommKitErrorSearchCardFailedImportFailed int = -906
	/*
	 * Failed to search card because required card is outdated.
	 */
	CommKitErrorSearchCardFailedRequiredIsOutdated int = -907
	/*
	 * Failed to export credentials because initializing crypto module failed.
	 */
	CommKitErrorExportCredsFailedInitCryptoFailed int = -1000
	/*
	 * Failed to export credentials because exporting private key failed.
	 */
	CommKitErrorExportCredsFailedExportPrivateKeyFailed int = -1001
	/*
	 * Failed to import credentials because initializing crypto module failed.
	 */
	CommKitErrorImportCredsFailedInitCryptoFailed int = -1002
	/*
	 * Failed to import credentials because parsing JSON failed.
	 */
	CommKitErrorImportCredsFailedParseFailed int = -1003
	/*
	 * Failed to import credentials because importing private key failed.
	 */
	CommKitErrorImportCredsFailedImportPrivateKeyFailed int = -1004
	/*
	 * Username validation failed because it's length exceeds the allowed maximum (20).
	 */
	CommKitErrorContactValidationFailedUsernameTooLong int = -1100
	/*
	 * Username validation failed because it contains invalid characters.
	 */
	CommKitErrorContactValidationFailedUsernameBadChars int = -1101
	/*
	 * Phone number validation failed because it does not conform to E.164 standard.
	 */
	CommKitErrorContactValidationFailedPhoneNumberBadFormat int = -1102
	/*
	 * Email validation failed because it has invalid format.
	 */
	CommKitErrorContactValidationFailedEmailBadFormat int = -1103
	/*
	 * The current user can not modify the group - permission violation.
	 */
	CommKitErrorModifyGroupFailedPermissionViolation int = -1200
	/*
	 * The current user can not access the group - permission violation.
	 */
	CommKitErrorAccessGroupFailedPermissionViolation int = -1201
	/*
	 * Failed to create group because underlying crypto module failed.
	 */
	CommKitErrorCreateGroupFailedCryptoFailed int = -1202
	/*
	 * Failed to import group epoch because parsing JSON failed.
	 */
	CommKitErrorImportGroupEpochFailedParseFailed int = -1203
	/*
	 * Failed to process group message because session id doesn't match.
	 */
	CommKitErrorProcessGroupMessageFailedSessionIdDoesntMatch int = -1204
	/*
	 * Failed to process group message because epoch not found.
	 */
	CommKitErrorProcessGroupMessageFailedEpochNotFound int = -1205
	/*
	 * Failed to process group message because wrong key type.
	 */
	CommKitErrorProcessGroupMessageFailedWrongKeyType int = -1206
	/*
	 * Failed to process group message because of invalid signature.
	 */
	CommKitErrorProcessGroupMessageFailedInvalidSignature int = -1207
	/*
	 * Failed to process group message because ed25519 failed.
	 */
	CommKitErrorProcessGroupMessageFailedEd25519Failed int = -1208
	/*
	 * Failed to process group message because of duplicated epoch.
	 */
	CommKitErrorProcessGroupMessageFailedDuplicateEpoch int = -1209
	/*
	 * Failed to process group message because plain text too long.
	 */
	CommKitErrorProcessGroupMessageFailedPlainTextTooLong int = -1210
	/*
	 * Failed to process group message because underlying crypto module failed.
	 */
	CommKitErrorProcessGroupMessageFailedCryptoFailed int = -1299
	/*
	 * Failed to decrypt regular message because of invalid encrypted message.
	 */
	CommKitErrorDecryptRegularMessageFailedInvalidEncryptedMessage int = -1301
	/*
	 * Failed to decrypt regular message because a private key can not decrypt.
	 */
	CommKitErrorDecryptRegularMessageFailedWrongPrivateKey int = -1302
	/*
	 * Failed to decrypt regular message because recipient was not found.
	 */
	CommKitErrorDecryptRegularMessageFailedRecipientNotFound int = -1303
	/*
	 * Failed to decrypt regular message because failed to verify signature.
	 */
	CommKitErrorDecryptRegularMessageFailedVerifySignature int = -1304
	/*
	 * Failed to decrypt regular message because underlying crypto module failed.
	 */
	CommKitErrorDecryptRegularMessageFailedCryptoFailed int = -1398
	/*
	 * Failed to encrypt regular message because underlying crypto module failed.
	 */
	CommKitErrorEncryptRegularMessageFailedCryptoFailed int = -1399
	/*
	 * Failed to perform contacts operation because send operation failed.
	 */
	CommKitErrorContactsFailedSendRequestFailed int = -1401
	/*
	 * Failed to perform contacts operation because response with error was returned.
	 */
	CommKitErrorContactsFailedResponseWithError int = -1402
	/*
	 * Failed to perform contacts operation because response parsing failed.
	 */
	CommKitErrorContactsFailedParseResponseFailed int = -1403
	/*
	 * Communicate with Cloud FS failed because send request failed.
	 */
	CommKitErrorCloudFsFailedSendRequestFailed int = -1500
	/*
	 * Cloud FS got a service error - internal server error (10000) - status 500.
	 */
	CommKitErrorCloudFsServiceErrorInternalServerError int = -1501
	/*
	 * Cloud FS got a service error - entry not found - status 404.
	 */
	CommKitErrorCloudFsFailedEntryNotFound int = -1502
	/*
	 * Cloud FS got a service error - identity is invalid (40001) - status 400.
	 */
	CommKitErrorCloudFsServiceErrorIdentityIsInvalid int = -1503
	/*
	 * Cloud FS got a service error - user not found (40002) - status 404.
	 */
	CommKitErrorCloudFsServiceErrorUserNotFound int = -1504
	/*
	 * Cloud FS got a service error - folder not found (40003) - status 404.
	 */
	CommKitErrorCloudFsServiceErrorFolderNotFound int = -1505
	/*
	 * Cloud FS got a service error - invalid filename (40004) - status 400.
	 */
	CommKitErrorCloudFsServiceErrorInvalidFilename int = -1506
	/*
	 * Cloud FS got a service error - invalid file id (40005) - status 400.
	 */
	CommKitErrorCloudFsServiceErrorInvalidFileId int = -1507
	/*
	 * Cloud FS got a service error - invalid file size (40006) - status 400.
	 */
	CommKitErrorCloudFsServiceErrorInvalidFileSize int = -1508
	/*
	 * Cloud FS got a service error - invalid file type (40007) - status 400.
	 */
	CommKitErrorCloudFsServiceErrorInvalidFileType int = -1509
	/*
	 * Cloud FS got a service error - invalid folder id (40008) - status 400.
	 */
	CommKitErrorCloudFsServiceErrorInvalidFolderId int = -1510
	/*
	 * Cloud FS got a service error - invalid folder name (40009) - status 400.
	 */
	CommKitErrorCloudFsServiceErrorInvalidFolderName int = -1511
	/*
	 * Cloud FS got a service error - invalid user permission (40010) - status 400.
	 */
	CommKitErrorCloudFsServiceErrorInvalidUserPermission int = -1512
	/*
	 * Cloud FS got a service error - group folder has limited depth (40011) - status 400.
	 */
	CommKitErrorCloudFsServiceErrorGroupFolderHasLimitedDepth int = -1513
	/*
	 * Cloud FS got a service error - permission denied (40012) - status 403.
	 */
	CommKitErrorCloudFsServiceErrorPermissionDenied int = -1514
	/*
	 * Cloud FS got a service error - key is not specified (40013) - status 400.
	 */
	CommKitErrorCloudFsServiceErrorKeyIsNotSpecified int = -1515
	/*
	 * Cloud FS got a service error - file with such name already exists (40014) - status 400.
	 */
	CommKitErrorCloudFsServiceErrorFileWithSuchNameAlreadyExists int = -1516
	/*
	 * Cloud FS got a service error - file not found (40015) - status 404.
	 */
	CommKitErrorCloudFsServiceErrorFileNotFound int = -1517
	/*
	 * Cloud FS got a service error - folder with such name already exists (40016) - status 400.
	 */
	CommKitErrorCloudFsServiceErrorFolderWithSuchNameAlreadyExists int = -1518
	/*
	 * Cloud FS got a service error - invalid group id (40017) - status 400.
	 */
	CommKitErrorCloudFsServiceErrorInvalidGroupId int = -1519
	/*
	 * Cloud FS got a service error - group not found (40018) - status 404.
	 */
	CommKitErrorCloudFsServiceErrorGroupNotFound int = -1520
	/*
	 * Cloud FS got a service error - undefined error - status 4xx.
	 */
	CommKitErrorCloudFsServiceErrorUndefined int = -1529
	/*
	 * Communicate with Cloud FS failed because met unexpected HTTP content type, expected application/protobuf.
	 */
	CommKitErrorCloudFsFailedResponseUnexpectedContentType int = -1530
	/*
	 * Communicate with Cloud FS failed because failed to parse response body.
	 */
	CommKitErrorCloudFsFailedParseResponseFailed int = -1531
	/*
	 * Cloud FS operation failed because key generation failed.
	 */
	CommKitErrorCloudFsFailedGenerateKeyFailed int = -1532
	/*
	 * Cloud FS operation failed because something went wrong during key encryption.
	 */
	CommKitErrorCloudFsFailedEncryptKeyFailed int = -1533
	/*
	 * Cloud FS operation failed because import key failed.
	 */
	CommKitErrorCloudFsFailedImportKeyFailed int = -1534
	/*
	 * Cloud FS operation failed because export key failed.
	 */
	CommKitErrorCloudFsFailedExportKeyFailed int = -1535
	/*
	 * Cloud FS operation failed because encrypted key has invalid format.
	 */
	CommKitErrorCloudFsFailedDecryptKeyFailedInvalidFormat int = -1536
	/*
	 * Cloud FS operation failed because encrypted key can not be decrypted with a given key.
	 */
	CommKitErrorCloudFsFailedDecryptKeyWrongKey int = -1537
	/*
	 * Cloud FS operation failed because encrypted key can not be decrypted due to signer mismatch.
	 */
	CommKitErrorCloudFsFailedDecryptKeySignerMismatch int = -1538
	/*
	 * Cloud FS operation failed because encrypted key can not be decrypted due to invalid signature.
	 */
	CommKitErrorCloudFsFailedDecryptKeyInvalidSignature int = -1539
)

func (obj *CommKitError) Error() string {
	return fmt.Sprintf("CommKitError{code: %v message: %s}", obj.Code, obj.Message)
}

/* Check given C status, and if it's not "success" then raise correspond error. */
func CommKitErrorHandleStatus(status C.vssq_status_t) error {
	if status != C.vssq_status_SUCCESS {
		switch status {
		case C.vssq_status_INTERNAL_ERROR:
			return &CommKitError{int(status), "Met internal inconsistency."}
		case C.vssq_status_RNG_FAILED:
			return &CommKitError{int(status), "Failed to initialize RNG."}
		case C.vssq_status_NOT_FOUND:
			return &CommKitError{int(status), "Generic error for any find operation."}
		case C.vssq_status_HTTP_SEND_FAILED:
			return &CommKitError{int(status), "Failed to send HTTP request."}
		case C.vssq_status_PARSE_EJABBERD_JWT_FAILED:
			return &CommKitError{int(status), "Failed to parse Ejabberd JWT."}
		case C.vssq_status_GENERATE_IDENTITY_FAILED:
			return &CommKitError{int(status), "Failed to generate identity."}
		case C.vssq_status_GENERATE_PRIVATE_KEY_FAILED:
			return &CommKitError{int(status), "Failed to generate private key."}
		case C.vssq_status_IMPORT_PRIVATE_KEY_FAILED:
			return &CommKitError{int(status), "Failed to import private key."}
		case C.vssq_status_EXPORT_PRIVATE_KEY_FAILED:
			return &CommKitError{int(status), "Failed to export private key."}
		case C.vssq_status_CALCULATE_KEY_ID_FAILED:
			return &CommKitError{int(status), "Failed to calculate key id."}
		case C.vssq_status_CREATE_CARD_MANAGER_FAILED:
			return &CommKitError{int(status), "Failed to create card manager."}
		case C.vssq_status_GENERATE_CARD_FAILED:
			return &CommKitError{int(status), "Failed to generate card."}
		case C.vssq_status_GENERATE_AUTH_HEADER_FAILED:
			return &CommKitError{int(status), "Failed to generate HTTP authentication header."}
		case C.vssq_status_REGISTER_CARD_FAILED_REQUEST_FAILED:
			return &CommKitError{int(status), "Failed to register card because send operation failed."}
		case C.vssq_status_REGISTER_CARD_FAILED_INVALID_RESPONSE:
			return &CommKitError{int(status), "Failed to register card because of invalid response."}
		case C.vssq_status_REGISTER_CARD_FAILED_RESPONSE_WITH_ERROR:
			return &CommKitError{int(status), "Failed to register card because response with error was returned."}
		case C.vssq_status_REGISTER_CARD_FAILED_PARSE_FAILED:
			return &CommKitError{int(status), "Failed to register card because parsing raw card failed."}
		case C.vssq_status_REGISTER_CARD_FAILED_IMPORT_FAILED:
			return &CommKitError{int(status), "Failed to register card because import raw card failed."}
		case C.vssq_status_GENERATE_BRAINKEY_FAILED_CRYPTO_FAILED:
			return &CommKitError{int(status), "Failed to generate brain key because of crypto fail."}
		case C.vssq_status_GENERATE_BRAINKEY_FAILED_RNG_FAILED:
			return &CommKitError{int(status), "Failed to generate brain key because of RNG fail."}
		case C.vssq_status_GENERATE_BRAINKEY_FAILED_BLIND_FAILED:
			return &CommKitError{int(status), "Failed to generate brain key because of blind fail."}
		case C.vssq_status_GENERATE_BRAINKEY_FAILED_DEBLIND_FAILED:
			return &CommKitError{int(status), "Failed to generate brain key because of deblind fail."}
		case C.vssq_status_GENERATE_BRAINKEY_FAILED_HARDENED_POINT_REQUEST_FAILED:
			return &CommKitError{int(status), "Failed to generate brain key because requesting hardened point from the service failed."}
		case C.vssq_status_GENERATE_BRAINKEY_FAILED_HARDENED_POINT_RESPONSE_WITH_ERROR:
			return &CommKitError{int(status), "Failed to generate brain key because hardened point response was returned with error."}
		case C.vssq_status_GENERATE_BRAINKEY_FAILED_HARDENED_POINT_PARSE_FAILED:
			return &CommKitError{int(status), "Failed to generate brain key because parsing hardened point response failed."}
		case C.vssq_status_KEYKNOX_FAILED_REQUEST_FAILED:
			return &CommKitError{int(status), "Failed to process Keyknox entry because send operation failed."}
		case C.vssq_status_KEYKNOX_FAILED_RESPONSE_WITH_ERROR:
			return &CommKitError{int(status), "Failed to process Keyknox entry because response with error was returned."}
		case C.vssq_status_KEYKNOX_FAILED_PARSE_RESPONSE_FAILED:
			return &CommKitError{int(status), "Failed to process Keyknox entry because response parsing failed."}
		case C.vssq_status_KEYKNOX_PACK_ENTRY_FAILED_EXPORT_PRIVATE_KEY_FAILED:
			return &CommKitError{int(status), "Failed to pack Keyknox entry because export private key failed."}
		case C.vssq_status_KEYKNOX_PACK_ENTRY_FAILED_ENCRYPT_FAILED:
			return &CommKitError{int(status), "Failed to pack Keyknox entry because encrypt operation failed."}
		case C.vssq_status_KEYKNOX_UNPACK_ENTRY_FAILED_DECRYPT_FAILED:
			return &CommKitError{int(status), "Failed to unpack Keyknox entry because decrypt operation failed."}
		case C.vssq_status_KEYKNOX_UNPACK_ENTRY_FAILED_VERIFY_SIGNATURE_FAILED:
			return &CommKitError{int(status), "Failed to unpack Keyknox entry because verifying signature failed."}
		case C.vssq_status_KEYKNOX_UNPACK_ENTRY_FAILED_PARSE_FAILED:
			return &CommKitError{int(status), "Failed to unpack Keyknox entry because parse operation failed."}
		case C.vssq_status_KEYKNOX_UNPACK_ENTRY_FAILED_IMPORT_PRIVATE_KEY_FAILED:
			return &CommKitError{int(status), "Failed to unpack Keyknox entry because import private key failed."}
		case C.vssq_status_REFRESH_JWT_FAILED_REQUEST_FAILED:
			return &CommKitError{int(status), "Failed to refresh JWT because send operation failed."}
		case C.vssq_status_REFRESH_JWT_FAILED_RESPONSE_WITH_ERROR:
			return &CommKitError{int(status), "Failed to refresh JWT because response with error was returned."}
		case C.vssq_status_REFRESH_JWT_FAILED_PARSE_RESPONSE_FAILED:
			return &CommKitError{int(status), "Failed to refresh JWT because response parsing failed."}
		case C.vssq_status_REFRESH_JWT_FAILED_PARSE_FAILED:
			return &CommKitError{int(status), "Failed to refresh JWT because JWT parsing failed."}
		case C.vssq_status_RESET_PASSWORD_FAILED_REQUEST_FAILED:
			return &CommKitError{int(status), "Failed to reset password because send operation failed."}
		case C.vssq_status_RESET_PASSWORD_FAILED_RESPONSE_WITH_ERROR:
			return &CommKitError{int(status), "Failed to reset password because response with error was returned."}
		case C.vssq_status_SEARCH_CARD_FAILED_INIT_FAILED:
			return &CommKitError{int(status), "Failed to search card because a card manager initialization failed."}
		case C.vssq_status_SEARCH_CARD_FAILED_REQUEST_FAILED:
			return &CommKitError{int(status), "Failed to search card because send operation failed."}
		case C.vssq_status_SEARCH_CARD_FAILED_RESPONSE_WITH_ERROR:
			return &CommKitError{int(status), "Failed to search card because response with error was returned."}
		case C.vssq_status_SEARCH_CARD_FAILED_REQUIRED_NOT_FOUND:
			return &CommKitError{int(status), "Failed to search card because required card was not found."}
		case C.vssq_status_SEARCH_CARD_FAILED_MULTIPLE_FOUND:
			return &CommKitError{int(status), "Failed to search card because found more then one active card."}
		case C.vssq_status_SEARCH_CARD_FAILED_PARSE_FAILED:
			return &CommKitError{int(status), "Failed to search card because parsing raw card failed."}
		case C.vssq_status_SEARCH_CARD_FAILED_IMPORT_FAILED:
			return &CommKitError{int(status), "Failed to search card because import raw card failed."}
		case C.vssq_status_SEARCH_CARD_FAILED_REQUIRED_IS_OUTDATED:
			return &CommKitError{int(status), "Failed to search card because required card is outdated."}
		case C.vssq_status_EXPORT_CREDS_FAILED_INIT_CRYPTO_FAILED:
			return &CommKitError{int(status), "Failed to export credentials because initializing crypto module failed."}
		case C.vssq_status_EXPORT_CREDS_FAILED_EXPORT_PRIVATE_KEY_FAILED:
			return &CommKitError{int(status), "Failed to export credentials because exporting private key failed."}
		case C.vssq_status_IMPORT_CREDS_FAILED_INIT_CRYPTO_FAILED:
			return &CommKitError{int(status), "Failed to import credentials because initializing crypto module failed."}
		case C.vssq_status_IMPORT_CREDS_FAILED_PARSE_FAILED:
			return &CommKitError{int(status), "Failed to import credentials because parsing JSON failed."}
		case C.vssq_status_IMPORT_CREDS_FAILED_IMPORT_PRIVATE_KEY_FAILED:
			return &CommKitError{int(status), "Failed to import credentials because importing private key failed."}
		case C.vssq_status_CONTACT_VALIDATION_FAILED_USERNAME_TOO_LONG:
			return &CommKitError{int(status), "Username validation failed because it's length exceeds the allowed maximum (20)."}
		case C.vssq_status_CONTACT_VALIDATION_FAILED_USERNAME_BAD_CHARS:
			return &CommKitError{int(status), "Username validation failed because it contains invalid characters."}
		case C.vssq_status_CONTACT_VALIDATION_FAILED_PHONE_NUMBER_BAD_FORMAT:
			return &CommKitError{int(status), "Phone number validation failed because it does not conform to E.164 standard."}
		case C.vssq_status_CONTACT_VALIDATION_FAILED_EMAIL_BAD_FORMAT:
			return &CommKitError{int(status), "Email validation failed because it has invalid format."}
		case C.vssq_status_MODIFY_GROUP_FAILED_PERMISSION_VIOLATION:
			return &CommKitError{int(status), "The current user can not modify the group - permission violation."}
		case C.vssq_status_ACCESS_GROUP_FAILED_PERMISSION_VIOLATION:
			return &CommKitError{int(status), "The current user can not access the group - permission violation."}
		case C.vssq_status_CREATE_GROUP_FAILED_CRYPTO_FAILED:
			return &CommKitError{int(status), "Failed to create group because underlying crypto module failed."}
		case C.vssq_status_IMPORT_GROUP_EPOCH_FAILED_PARSE_FAILED:
			return &CommKitError{int(status), "Failed to import group epoch because parsing JSON failed."}
		case C.vssq_status_PROCESS_GROUP_MESSAGE_FAILED_SESSION_ID_DOESNT_MATCH:
			return &CommKitError{int(status), "Failed to process group message because session id doesn't match."}
		case C.vssq_status_PROCESS_GROUP_MESSAGE_FAILED_EPOCH_NOT_FOUND:
			return &CommKitError{int(status), "Failed to process group message because epoch not found."}
		case C.vssq_status_PROCESS_GROUP_MESSAGE_FAILED_WRONG_KEY_TYPE:
			return &CommKitError{int(status), "Failed to process group message because wrong key type."}
		case C.vssq_status_PROCESS_GROUP_MESSAGE_FAILED_INVALID_SIGNATURE:
			return &CommKitError{int(status), "Failed to process group message because of invalid signature."}
		case C.vssq_status_PROCESS_GROUP_MESSAGE_FAILED_ED25519_FAILED:
			return &CommKitError{int(status), "Failed to process group message because ed25519 failed."}
		case C.vssq_status_PROCESS_GROUP_MESSAGE_FAILED_DUPLICATE_EPOCH:
			return &CommKitError{int(status), "Failed to process group message because of duplicated epoch."}
		case C.vssq_status_PROCESS_GROUP_MESSAGE_FAILED_PLAIN_TEXT_TOO_LONG:
			return &CommKitError{int(status), "Failed to process group message because plain text too long."}
		case C.vssq_status_PROCESS_GROUP_MESSAGE_FAILED_CRYPTO_FAILED:
			return &CommKitError{int(status), "Failed to process group message because underlying crypto module failed."}
		case C.vssq_status_DECRYPT_REGULAR_MESSAGE_FAILED_INVALID_ENCRYPTED_MESSAGE:
			return &CommKitError{int(status), "Failed to decrypt regular message because of invalid encrypted message."}
		case C.vssq_status_DECRYPT_REGULAR_MESSAGE_FAILED_WRONG_PRIVATE_KEY:
			return &CommKitError{int(status), "Failed to decrypt regular message because a private key can not decrypt."}
		case C.vssq_status_DECRYPT_REGULAR_MESSAGE_FAILED_RECIPIENT_NOT_FOUND:
			return &CommKitError{int(status), "Failed to decrypt regular message because recipient was not found."}
		case C.vssq_status_DECRYPT_REGULAR_MESSAGE_FAILED_VERIFY_SIGNATURE:
			return &CommKitError{int(status), "Failed to decrypt regular message because failed to verify signature."}
		case C.vssq_status_DECRYPT_REGULAR_MESSAGE_FAILED_CRYPTO_FAILED:
			return &CommKitError{int(status), "Failed to decrypt regular message because underlying crypto module failed."}
		case C.vssq_status_ENCRYPT_REGULAR_MESSAGE_FAILED_CRYPTO_FAILED:
			return &CommKitError{int(status), "Failed to encrypt regular message because underlying crypto module failed."}
		case C.vssq_status_CONTACTS_FAILED_SEND_REQUEST_FAILED:
			return &CommKitError{int(status), "Failed to perform contacts operation because send operation failed."}
		case C.vssq_status_CONTACTS_FAILED_RESPONSE_WITH_ERROR:
			return &CommKitError{int(status), "Failed to perform contacts operation because response with error was returned."}
		case C.vssq_status_CONTACTS_FAILED_PARSE_RESPONSE_FAILED:
			return &CommKitError{int(status), "Failed to perform contacts operation because response parsing failed."}
		case C.vssq_status_CLOUD_FS_FAILED_SEND_REQUEST_FAILED:
			return &CommKitError{int(status), "Communicate with Cloud FS failed because send request failed."}
		case C.vssq_status_CLOUD_FS_SERVICE_ERROR_INTERNAL_SERVER_ERROR:
			return &CommKitError{int(status), "Cloud FS got a service error - internal server error (10000) - status 500."}
		case C.vssq_status_CLOUD_FS_FAILED_ENTRY_NOT_FOUND:
			return &CommKitError{int(status), "Cloud FS got a service error - entry not found - status 404."}
		case C.vssq_status_CLOUD_FS_SERVICE_ERROR_IDENTITY_IS_INVALID:
			return &CommKitError{int(status), "Cloud FS got a service error - identity is invalid (40001) - status 400."}
		case C.vssq_status_CLOUD_FS_SERVICE_ERROR_USER_NOT_FOUND:
			return &CommKitError{int(status), "Cloud FS got a service error - user not found (40002) - status 404."}
		case C.vssq_status_CLOUD_FS_SERVICE_ERROR_FOLDER_NOT_FOUND:
			return &CommKitError{int(status), "Cloud FS got a service error - folder not found (40003) - status 404."}
		case C.vssq_status_CLOUD_FS_SERVICE_ERROR_INVALID_FILENAME:
			return &CommKitError{int(status), "Cloud FS got a service error - invalid filename (40004) - status 400."}
		case C.vssq_status_CLOUD_FS_SERVICE_ERROR_INVALID_FILE_ID:
			return &CommKitError{int(status), "Cloud FS got a service error - invalid file id (40005) - status 400."}
		case C.vssq_status_CLOUD_FS_SERVICE_ERROR_INVALID_FILE_SIZE:
			return &CommKitError{int(status), "Cloud FS got a service error - invalid file size (40006) - status 400."}
		case C.vssq_status_CLOUD_FS_SERVICE_ERROR_INVALID_FILE_TYPE:
			return &CommKitError{int(status), "Cloud FS got a service error - invalid file type (40007) - status 400."}
		case C.vssq_status_CLOUD_FS_SERVICE_ERROR_INVALID_FOLDER_ID:
			return &CommKitError{int(status), "Cloud FS got a service error - invalid folder id (40008) - status 400."}
		case C.vssq_status_CLOUD_FS_SERVICE_ERROR_INVALID_FOLDER_NAME:
			return &CommKitError{int(status), "Cloud FS got a service error - invalid folder name (40009) - status 400."}
		case C.vssq_status_CLOUD_FS_SERVICE_ERROR_INVALID_USER_PERMISSION:
			return &CommKitError{int(status), "Cloud FS got a service error - invalid user permission (40010) - status 400."}
		case C.vssq_status_CLOUD_FS_SERVICE_ERROR_GROUP_FOLDER_HAS_LIMITED_DEPTH:
			return &CommKitError{int(status), "Cloud FS got a service error - group folder has limited depth (40011) - status 400."}
		case C.vssq_status_CLOUD_FS_SERVICE_ERROR_PERMISSION_DENIED:
			return &CommKitError{int(status), "Cloud FS got a service error - permission denied (40012) - status 403."}
		case C.vssq_status_CLOUD_FS_SERVICE_ERROR_KEY_IS_NOT_SPECIFIED:
			return &CommKitError{int(status), "Cloud FS got a service error - key is not specified (40013) - status 400."}
		case C.vssq_status_CLOUD_FS_SERVICE_ERROR_FILE_WITH_SUCH_NAME_ALREADY_EXISTS:
			return &CommKitError{int(status), "Cloud FS got a service error - file with such name already exists (40014) - status 400."}
		case C.vssq_status_CLOUD_FS_SERVICE_ERROR_FILE_NOT_FOUND:
			return &CommKitError{int(status), "Cloud FS got a service error - file not found (40015) - status 404."}
		case C.vssq_status_CLOUD_FS_SERVICE_ERROR_FOLDER_WITH_SUCH_NAME_ALREADY_EXISTS:
			return &CommKitError{int(status), "Cloud FS got a service error - folder with such name already exists (40016) - status 400."}
		case C.vssq_status_CLOUD_FS_SERVICE_ERROR_INVALID_GROUP_ID:
			return &CommKitError{int(status), "Cloud FS got a service error - invalid group id (40017) - status 400."}
		case C.vssq_status_CLOUD_FS_SERVICE_ERROR_GROUP_NOT_FOUND:
			return &CommKitError{int(status), "Cloud FS got a service error - group not found (40018) - status 404."}
		case C.vssq_status_CLOUD_FS_SERVICE_ERROR_UNDEFINED:
			return &CommKitError{int(status), "Cloud FS got a service error - undefined error - status 4xx."}
		case C.vssq_status_CLOUD_FS_FAILED_RESPONSE_UNEXPECTED_CONTENT_TYPE:
			return &CommKitError{int(status), "Communicate with Cloud FS failed because met unexpected HTTP content type, expected application/protobuf."}
		case C.vssq_status_CLOUD_FS_FAILED_PARSE_RESPONSE_FAILED:
			return &CommKitError{int(status), "Communicate with Cloud FS failed because failed to parse response body."}
		case C.vssq_status_CLOUD_FS_FAILED_GENERATE_KEY_FAILED:
			return &CommKitError{int(status), "Cloud FS operation failed because key generation failed."}
		case C.vssq_status_CLOUD_FS_FAILED_ENCRYPT_KEY_FAILED:
			return &CommKitError{int(status), "Cloud FS operation failed because something went wrong during key encryption."}
		case C.vssq_status_CLOUD_FS_FAILED_IMPORT_KEY_FAILED:
			return &CommKitError{int(status), "Cloud FS operation failed because import key failed."}
		case C.vssq_status_CLOUD_FS_FAILED_EXPORT_KEY_FAILED:
			return &CommKitError{int(status), "Cloud FS operation failed because export key failed."}
		case C.vssq_status_CLOUD_FS_FAILED_DECRYPT_KEY_FAILED_INVALID_FORMAT:
			return &CommKitError{int(status), "Cloud FS operation failed because encrypted key has invalid format."}
		case C.vssq_status_CLOUD_FS_FAILED_DECRYPT_KEY_WRONG_KEY:
			return &CommKitError{int(status), "Cloud FS operation failed because encrypted key can not be decrypted with a given key."}
		case C.vssq_status_CLOUD_FS_FAILED_DECRYPT_KEY_SIGNER_MISMATCH:
			return &CommKitError{int(status), "Cloud FS operation failed because encrypted key can not be decrypted due to signer mismatch."}
		case C.vssq_status_CLOUD_FS_FAILED_DECRYPT_KEY_INVALID_SIGNATURE:
			return &CommKitError{int(status), "Cloud FS operation failed because encrypted key can not be decrypted due to invalid signature."}
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
