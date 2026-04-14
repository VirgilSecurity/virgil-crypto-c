#define VSCF_HANDLE_STATUS(status) do { if(status != vscf_status_SUCCESS) { vscf_handle_throw_exception(status); } } while (false)

zend_class_entry* vscf_exception_ce;

void
vscf_handle_throw_exception(vscf_status_t status) {

    switch(status) {

    case vscf_status_SUCCESS:
        break;
    case vscf_status_ERROR_BAD_ARGUMENTS:
        zend_throw_exception_ex(vscf_exception_ce, -1, "This error should not be returned if assertions is enabled.");
        break;
    case vscf_status_ERROR_UNINITIALIZED:
        zend_throw_exception_ex(vscf_exception_ce, -2, "Can be used to define that not all context prerequisites are satisfied. Note, this error should not be returned if assertions is enabled.");
        break;
    case vscf_status_ERROR_UNHANDLED_THIRDPARTY_ERROR:
        zend_throw_exception_ex(vscf_exception_ce, -3, "Define that error code from one of third-party module was not handled. Note, this error should not be returned if assertions is enabled.");
        break;
    case vscf_status_ERROR_SMALL_BUFFER:
        zend_throw_exception_ex(vscf_exception_ce, -101, "Buffer capacity is not enough to hold result.");
        break;
    case vscf_status_ERROR_UNSUPPORTED_ALGORITHM:
        zend_throw_exception_ex(vscf_exception_ce, -200, "Unsupported algorithm.");
        break;
    case vscf_status_ERROR_AUTH_FAILED:
        zend_throw_exception_ex(vscf_exception_ce, -201, "Authentication failed during decryption.");
        break;
    case vscf_status_ERROR_OUT_OF_DATA:
        zend_throw_exception_ex(vscf_exception_ce, -202, "Attempt to read data out of buffer bounds.");
        break;
    case vscf_status_ERROR_BAD_ASN1:
        zend_throw_exception_ex(vscf_exception_ce, -203, "ASN.1 encoded data is corrupted.");
        break;
    case vscf_status_ERROR_ASN1_LOSSY_TYPE_NARROWING:
        zend_throw_exception_ex(vscf_exception_ce, -204, "Attempt to read ASN.1 type that is bigger then requested C type.");
        break;
    case vscf_status_ERROR_BAD_PKCS1_PUBLIC_KEY:
        zend_throw_exception_ex(vscf_exception_ce, -205, "ASN.1 representation of PKCS#1 public key is corrupted.");
        break;
    case vscf_status_ERROR_BAD_PKCS1_PRIVATE_KEY:
        zend_throw_exception_ex(vscf_exception_ce, -206, "ASN.1 representation of PKCS#1 private key is corrupted.");
        break;
    case vscf_status_ERROR_BAD_PKCS8_PUBLIC_KEY:
        zend_throw_exception_ex(vscf_exception_ce, -207, "ASN.1 representation of PKCS#8 public key is corrupted.");
        break;
    case vscf_status_ERROR_BAD_PKCS8_PRIVATE_KEY:
        zend_throw_exception_ex(vscf_exception_ce, -208, "ASN.1 representation of PKCS#8 private key is corrupted.");
        break;
    case vscf_status_ERROR_BAD_ENCRYPTED_DATA:
        zend_throw_exception_ex(vscf_exception_ce, -209, "Encrypted data is corrupted.");
        break;
    case vscf_status_ERROR_RANDOM_FAILED:
        zend_throw_exception_ex(vscf_exception_ce, -210, "Underlying random operation returns error.");
        break;
    case vscf_status_ERROR_KEY_GENERATION_FAILED:
        zend_throw_exception_ex(vscf_exception_ce, -211, "Generation of the private or secret key failed.");
        break;
    case vscf_status_ERROR_ENTROPY_SOURCE_FAILED:
        zend_throw_exception_ex(vscf_exception_ce, -212, "One of the entropy sources failed.");
        break;
    case vscf_status_ERROR_RNG_REQUESTED_DATA_TOO_BIG:
        zend_throw_exception_ex(vscf_exception_ce, -213, "Requested data to be generated is too big.");
        break;
    case vscf_status_ERROR_BAD_BASE64:
        zend_throw_exception_ex(vscf_exception_ce, -214, "Base64 encoded string contains invalid characters.");
        break;
    case vscf_status_ERROR_BAD_PEM:
        zend_throw_exception_ex(vscf_exception_ce, -215, "PEM data is corrupted.");
        break;
    case vscf_status_ERROR_SHARED_KEY_EXCHANGE_FAILED:
        zend_throw_exception_ex(vscf_exception_ce, -216, "Exchange key return zero.");
        break;
    case vscf_status_ERROR_BAD_ED25519_PUBLIC_KEY:
        zend_throw_exception_ex(vscf_exception_ce, -217, "Ed25519 public key is corrupted.");
        break;
    case vscf_status_ERROR_BAD_ED25519_PRIVATE_KEY:
        zend_throw_exception_ex(vscf_exception_ce, -218, "Ed25519 private key is corrupted.");
        break;
    case vscf_status_ERROR_BAD_CURVE25519_PUBLIC_KEY:
        zend_throw_exception_ex(vscf_exception_ce, -219, "CURVE25519 public key is corrupted.");
        break;
    case vscf_status_ERROR_BAD_CURVE25519_PRIVATE_KEY:
        zend_throw_exception_ex(vscf_exception_ce, -220, "CURVE25519 private key is corrupted.");
        break;
    case vscf_status_ERROR_BAD_SEC1_PUBLIC_KEY:
        zend_throw_exception_ex(vscf_exception_ce, -221, "Elliptic curve public key format is corrupted see RFC 5480.");
        break;
    case vscf_status_ERROR_BAD_SEC1_PRIVATE_KEY:
        zend_throw_exception_ex(vscf_exception_ce, -222, "Elliptic curve public key format is corrupted see RFC 5915.");
        break;
    case vscf_status_ERROR_BAD_DER_PUBLIC_KEY:
        zend_throw_exception_ex(vscf_exception_ce, -223, "ASN.1 representation of a public key is corrupted.");
        break;
    case vscf_status_ERROR_BAD_DER_PRIVATE_KEY:
        zend_throw_exception_ex(vscf_exception_ce, -224, "ASN.1 representation of a private key is corrupted.");
        break;
    case vscf_status_ERROR_MISMATCH_PUBLIC_KEY_AND_ALGORITHM:
        zend_throw_exception_ex(vscf_exception_ce, -225, "Key algorithm does not accept given type of public key.");
        break;
    case vscf_status_ERROR_MISMATCH_PRIVATE_KEY_AND_ALGORITHM:
        zend_throw_exception_ex(vscf_exception_ce, -226, "Key algorithm does not accept given type of private key.");
        break;
    case vscf_status_ERROR_BAD_FALCON_PUBLIC_KEY:
        zend_throw_exception_ex(vscf_exception_ce, -227, "Post-quantum Falcon-Sign public key is corrupted.");
        break;
    case vscf_status_ERROR_BAD_FALCON_PRIVATE_KEY:
        zend_throw_exception_ex(vscf_exception_ce, -228, "Post-quantum Falcon-Sign private key is corrupted.");
        break;
    case vscf_status_ERROR_ROUND5:
        zend_throw_exception_ex(vscf_exception_ce, -229, "Generic Round5 library error.");
        break;
    case vscf_status_ERROR_BAD_ROUND5_PUBLIC_KEY:
        zend_throw_exception_ex(vscf_exception_ce, -230, "Post-quantum NIST Round5 public key is corrupted.");
        break;
    case vscf_status_ERROR_BAD_ROUND5_PRIVATE_KEY:
        zend_throw_exception_ex(vscf_exception_ce, -231, "Post-quantum NIST Round5 private key is corrupted.");
        break;
    case vscf_status_ERROR_BAD_COMPOUND_PUBLIC_KEY:
        zend_throw_exception_ex(vscf_exception_ce, -232, "Compound public key is corrupted.");
        break;
    case vscf_status_ERROR_BAD_COMPOUND_PRIVATE_KEY:
        zend_throw_exception_ex(vscf_exception_ce, -233, "Compound private key is corrupted.");
        break;
    case vscf_status_ERROR_BAD_HYBRID_PUBLIC_KEY:
        zend_throw_exception_ex(vscf_exception_ce, -234, "Compound public hybrid key is corrupted.");
        break;
    case vscf_status_ERROR_BAD_HYBRID_PRIVATE_KEY:
        zend_throw_exception_ex(vscf_exception_ce, -235, "Compound private hybrid key is corrupted.");
        break;
    case vscf_status_ERROR_BAD_ASN1_ALGORITHM:
        zend_throw_exception_ex(vscf_exception_ce, -236, "ASN.1 AlgorithmIdentifer is corrupted.");
        break;
    case vscf_status_ERROR_BAD_ASN1_ALGORITHM_ECC:
        zend_throw_exception_ex(vscf_exception_ce, -237, "ASN.1 AlgorithmIdentifer with ECParameters is corrupted.");
        break;
    case vscf_status_ERROR_BAD_ASN1_ALGORITHM_COMPOUND_KEY:
        zend_throw_exception_ex(vscf_exception_ce, -238, "ASN.1 AlgorithmIdentifer with CompoundKeyParams is corrupted.");
        break;
    case vscf_status_ERROR_BAD_ASN1_ALGORITHM_HYBRID_KEY:
        zend_throw_exception_ex(vscf_exception_ce, -239, "ASN.1 AlgorithmIdentifer with HybridKeyParams is corrupted.");
        break;
    case vscf_status_ERROR_NO_MESSAGE_INFO:
        zend_throw_exception_ex(vscf_exception_ce, -301, "Decryption failed, because message info was not given explicitly, and was not part of an encrypted message.");
        break;
    case vscf_status_ERROR_BAD_MESSAGE_INFO:
        zend_throw_exception_ex(vscf_exception_ce, -302, "Message Info is corrupted.");
        break;
    case vscf_status_ERROR_KEY_RECIPIENT_IS_NOT_FOUND:
        zend_throw_exception_ex(vscf_exception_ce, -303, "Recipient defined with id is not found within message info during data decryption.");
        break;
    case vscf_status_ERROR_KEY_RECIPIENT_PRIVATE_KEY_IS_WRONG:
        zend_throw_exception_ex(vscf_exception_ce, -304, "Content encryption key can not be decrypted with a given private key.");
        break;
    case vscf_status_ERROR_PASSWORD_RECIPIENT_PASSWORD_IS_WRONG:
        zend_throw_exception_ex(vscf_exception_ce, -305, "Content encryption key can not be decrypted with a given password.");
        break;
    case vscf_status_ERROR_MESSAGE_INFO_CUSTOM_PARAM_NOT_FOUND:
        zend_throw_exception_ex(vscf_exception_ce, -306, "Custom parameter with a given key is not found within message info.");
        break;
    case vscf_status_ERROR_MESSAGE_INFO_CUSTOM_PARAM_TYPE_MISMATCH:
        zend_throw_exception_ex(vscf_exception_ce, -307, "A custom parameter with a given key is found, but the requested value type does not correspond to the actual type.");
        break;
    case vscf_status_ERROR_BAD_SIGNATURE:
        zend_throw_exception_ex(vscf_exception_ce, -308, "Signature format is corrupted.");
        break;
    case vscf_status_ERROR_BAD_MESSAGE_INFO_FOOTER:
        zend_throw_exception_ex(vscf_exception_ce, -309, "Message Info footer is corrupted.");
        break;
    case vscf_status_ERROR_INVALID_BRAINKEY_PASSWORD_LEN:
        zend_throw_exception_ex(vscf_exception_ce, -401, "Brainkey password length is out of range.");
        break;
    case vscf_status_ERROR_INVALID_BRAINKEY_FACTOR_LEN:
        zend_throw_exception_ex(vscf_exception_ce, -402, "Brainkey number length should be 32 byte.");
        break;
    case vscf_status_ERROR_INVALID_BRAINKEY_POINT_LEN:
        zend_throw_exception_ex(vscf_exception_ce, -403, "Brainkey point length should be 65 bytes.");
        break;
    case vscf_status_ERROR_INVALID_BRAINKEY_KEY_NAME_LEN:
        zend_throw_exception_ex(vscf_exception_ce, -404, "Brainkey name is out of range.");
        break;
    case vscf_status_ERROR_BRAINKEY_INTERNAL:
        zend_throw_exception_ex(vscf_exception_ce, -405, "Brainkey internal error.");
        break;
    case vscf_status_ERROR_BRAINKEY_INVALID_POINT:
        zend_throw_exception_ex(vscf_exception_ce, -406, "Brainkey point is invalid.");
        break;
    case vscf_status_ERROR_INVALID_BRAINKEY_FACTOR_BUFFER_LEN:
        zend_throw_exception_ex(vscf_exception_ce, -407, "Brainkey number buffer length capacity should be >= 32 byte.");
        break;
    case vscf_status_ERROR_INVALID_BRAINKEY_POINT_BUFFER_LEN:
        zend_throw_exception_ex(vscf_exception_ce, -408, "Brainkey point buffer length capacity should be >= 32 byte.");
        break;
    case vscf_status_ERROR_INVALID_BRAINKEY_SEED_BUFFER_LEN:
        zend_throw_exception_ex(vscf_exception_ce, -409, "Brainkey seed buffer length capacity should be >= 32 byte.");
        break;
    case vscf_status_ERROR_INVALID_IDENTITY_SECRET:
        zend_throw_exception_ex(vscf_exception_ce, -410, "Brainkey identity secret is invalid.");
        break;
    case vscf_status_ERROR_INVALID_KEM_ENCAPSULATED_KEY:
        zend_throw_exception_ex(vscf_exception_ce, -411, "KEM encapsulated key is invalid or does not correspond to the private key.");
        break;
    case vscf_status_ERROR_INVALID_PADDING:
        zend_throw_exception_ex(vscf_exception_ce, -501, "Invalid padding.");
        break;
    case vscf_status_ERROR_PROTOBUF:
        zend_throw_exception_ex(vscf_exception_ce, -601, "Protobuf error.");
        break;
    case vscf_status_ERROR_SESSION_ID_DOESNT_MATCH:
        zend_throw_exception_ex(vscf_exception_ce, -701, "Session id doesnt match.");
        break;
    case vscf_status_ERROR_EPOCH_NOT_FOUND:
        zend_throw_exception_ex(vscf_exception_ce, -702, "Epoch not found.");
        break;
    case vscf_status_ERROR_WRONG_KEY_TYPE:
        zend_throw_exception_ex(vscf_exception_ce, -703, "Wrong key type.");
        break;
    case vscf_status_ERROR_INVALID_SIGNATURE:
        zend_throw_exception_ex(vscf_exception_ce, -704, "Invalid signature.");
        break;
    case vscf_status_ERROR_ED25519:
        zend_throw_exception_ex(vscf_exception_ce, -705, "Ed25519 error.");
        break;
    case vscf_status_ERROR_DUPLICATE_EPOCH:
        zend_throw_exception_ex(vscf_exception_ce, -706, "Duplicate epoch.");
        break;
    case vscf_status_ERROR_PLAIN_TEXT_TOO_LONG:
        zend_throw_exception_ex(vscf_exception_ce, -707, "Plain text too long.");
        break;
    }
}
