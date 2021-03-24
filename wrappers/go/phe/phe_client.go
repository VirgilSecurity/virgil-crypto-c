package phe

// #include <virgil/crypto/phe/vsce_phe_public.h>
import "C"
import unsafe "unsafe"
import "runtime"
import foundation "virgil/foundation"

/*
* Class for client-side PHE crypto operations.
* This class is thread-safe in case if VSCE_MULTI_THREADING defined.
 */
type PheClient struct {
	cCtx *C.vsce_phe_client_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *PheClient) Ctx() uintptr {
	return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewPheClient() *PheClient {
	ctx := C.vsce_phe_client_new()
	obj := &PheClient{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*PheClient).Delete)
	return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewPheClientWithCtx(pointer unsafe.Pointer) *PheClient {
	ctx := (*C.vsce_phe_client_t /*ct2*/)(pointer)
	obj := &PheClient{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*PheClient).Delete)
	return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewPheClientCopy(pointer unsafe.Pointer) *PheClient {
	ctx := (*C.vsce_phe_client_t /*ct2*/)(pointer)
	obj := &PheClient{
		cCtx: C.vsce_phe_client_shallow_copy(ctx),
	}
	runtime.SetFinalizer(obj, (*PheClient).Delete)
	return obj
}

/*
* Release underlying C context.
 */
func (obj *PheClient) Delete() {
	if obj == nil {
		return
	}
	runtime.SetFinalizer(obj, nil)
	obj.delete()
}

/*
* Release underlying C context.
 */
func (obj *PheClient) delete() {
	C.vsce_phe_client_delete(obj.cCtx)
}

/*
* Random used for key generation, proofs, etc.
 */
func (obj *PheClient) SetRandom(random foundation.Random) {
	C.vsce_phe_client_release_random(obj.cCtx)
	C.vsce_phe_client_use_random(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(random.Ctx())))

	runtime.KeepAlive(random)
	runtime.KeepAlive(obj)
}

/*
* Random used for crypto operations to make them const-time
 */
func (obj *PheClient) SetOperationRandom(operationRandom foundation.Random) {
	C.vsce_phe_client_release_operation_random(obj.cCtx)
	C.vsce_phe_client_use_operation_random(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(operationRandom.Ctx())))

	runtime.KeepAlive(operationRandom)
	runtime.KeepAlive(obj)
}

/*
* Setups dependencies with default values.
 */
func (obj *PheClient) SetupDefaults() error {
	proxyResult := /*pr4*/ C.vsce_phe_client_setup_defaults(obj.cCtx)

	err := PheErrorHandleStatus(proxyResult)
	if err != nil {
		return err
	}

	runtime.KeepAlive(obj)

	return nil
}

/*
* Sets client private and server public key
* Call this method before any other methods except `update enrollment record` and `generate client private key`
* This function should be called only once
 */
func (obj *PheClient) SetKeys(clientPrivateKey []byte, serverPublicKey []byte) error {
	clientPrivateKeyData := helperWrapData(clientPrivateKey)
	serverPublicKeyData := helperWrapData(serverPublicKey)

	proxyResult := /*pr4*/ C.vsce_phe_client_set_keys(obj.cCtx, clientPrivateKeyData, serverPublicKeyData)

	err := PheErrorHandleStatus(proxyResult)
	if err != nil {
		return err
	}

	runtime.KeepAlive(obj)

	return nil
}

/*
* Generates client private key
 */
func (obj *PheClient) GenerateClientPrivateKey() ([]byte, error) {
	clientPrivateKeyBuf, clientPrivateKeyBufErr := newBuffer(int(PheCommonPhePrivateKeyLength /* lg4 */))
	if clientPrivateKeyBufErr != nil {
		return nil, clientPrivateKeyBufErr
	}
	defer clientPrivateKeyBuf.delete()

	proxyResult := /*pr4*/ C.vsce_phe_client_generate_client_private_key(obj.cCtx, clientPrivateKeyBuf.ctx)

	err := PheErrorHandleStatus(proxyResult)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(obj)

	return clientPrivateKeyBuf.getData() /* r7 */, nil
}

/*
* Buffer size needed to fit EnrollmentRecord
 */
func (obj *PheClient) EnrollmentRecordLen() uint {
	proxyResult := /*pr4*/ C.vsce_phe_client_enrollment_record_len(obj.cCtx)

	runtime.KeepAlive(obj)

	return uint(proxyResult) /* r9 */
}

/*
* Uses fresh EnrollmentResponse from PHE server (see get enrollment func) and user's password (or its hash) to create
* a new EnrollmentRecord which is then supposed to be stored in a database for further authentication
* Also generates a random seed which then can be used to generate symmetric or private key to protect user's data
 */
func (obj *PheClient) EnrollAccount(enrollmentResponse []byte, password []byte) ([]byte, []byte, error) {
	enrollmentRecordBuf, enrollmentRecordBufErr := newBuffer(int(obj.EnrollmentRecordLen() /* lg2 */))
	if enrollmentRecordBufErr != nil {
		return nil, nil, enrollmentRecordBufErr
	}
	defer enrollmentRecordBuf.delete()

	accountKeyBuf, accountKeyBufErr := newBuffer(int(PheCommonPheAccountKeyLength /* lg4 */))
	if accountKeyBufErr != nil {
		return nil, nil, accountKeyBufErr
	}
	defer accountKeyBuf.delete()
	enrollmentResponseData := helperWrapData(enrollmentResponse)
	passwordData := helperWrapData(password)

	proxyResult := /*pr4*/ C.vsce_phe_client_enroll_account(obj.cCtx, enrollmentResponseData, passwordData, enrollmentRecordBuf.ctx, accountKeyBuf.ctx)

	err := PheErrorHandleStatus(proxyResult)
	if err != nil {
		return nil, nil, err
	}

	runtime.KeepAlive(obj)

	return enrollmentRecordBuf.getData() /* r7 */, accountKeyBuf.getData() /* r7 */, nil
}

/*
* Buffer size needed to fit VerifyPasswordRequest
 */
func (obj *PheClient) VerifyPasswordRequestLen() uint {
	proxyResult := /*pr4*/ C.vsce_phe_client_verify_password_request_len(obj.cCtx)

	runtime.KeepAlive(obj)

	return uint(proxyResult) /* r9 */
}

/*
* Creates a request for further password verification at the PHE server side.
 */
func (obj *PheClient) CreateVerifyPasswordRequest(password []byte, enrollmentRecord []byte) ([]byte, error) {
	verifyPasswordRequestBuf, verifyPasswordRequestBufErr := newBuffer(int(obj.VerifyPasswordRequestLen() /* lg2 */))
	if verifyPasswordRequestBufErr != nil {
		return nil, verifyPasswordRequestBufErr
	}
	defer verifyPasswordRequestBuf.delete()
	passwordData := helperWrapData(password)
	enrollmentRecordData := helperWrapData(enrollmentRecord)

	proxyResult := /*pr4*/ C.vsce_phe_client_create_verify_password_request(obj.cCtx, passwordData, enrollmentRecordData, verifyPasswordRequestBuf.ctx)

	err := PheErrorHandleStatus(proxyResult)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(obj)

	return verifyPasswordRequestBuf.getData() /* r7 */, nil
}

/*
* Verifies PHE server's answer
* If login succeeded, extracts account key
* If login failed account key will be empty
 */
func (obj *PheClient) CheckResponseAndDecrypt(password []byte, enrollmentRecord []byte, verifyPasswordResponse []byte) ([]byte, error) {
	accountKeyBuf, accountKeyBufErr := newBuffer(int(PheCommonPheAccountKeyLength /* lg4 */))
	if accountKeyBufErr != nil {
		return nil, accountKeyBufErr
	}
	defer accountKeyBuf.delete()
	passwordData := helperWrapData(password)
	enrollmentRecordData := helperWrapData(enrollmentRecord)
	verifyPasswordResponseData := helperWrapData(verifyPasswordResponse)

	proxyResult := /*pr4*/ C.vsce_phe_client_check_response_and_decrypt(obj.cCtx, passwordData, enrollmentRecordData, verifyPasswordResponseData, accountKeyBuf.ctx)

	err := PheErrorHandleStatus(proxyResult)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(obj)

	return accountKeyBuf.getData() /* r7 */, nil
}

/*
* Updates client's private key and server's public key using server's update token
* Use output values to instantiate new client instance with new keys
 */
func (obj *PheClient) RotateKeys(updateToken []byte) ([]byte, []byte, error) {
	newClientPrivateKeyBuf, newClientPrivateKeyBufErr := newBuffer(int(PheCommonPhePrivateKeyLength /* lg4 */))
	if newClientPrivateKeyBufErr != nil {
		return nil, nil, newClientPrivateKeyBufErr
	}
	defer newClientPrivateKeyBuf.delete()

	newServerPublicKeyBuf, newServerPublicKeyBufErr := newBuffer(int(PheCommonPhePublicKeyLength /* lg4 */))
	if newServerPublicKeyBufErr != nil {
		return nil, nil, newServerPublicKeyBufErr
	}
	defer newServerPublicKeyBuf.delete()
	updateTokenData := helperWrapData(updateToken)

	proxyResult := /*pr4*/ C.vsce_phe_client_rotate_keys(obj.cCtx, updateTokenData, newClientPrivateKeyBuf.ctx, newServerPublicKeyBuf.ctx)

	err := PheErrorHandleStatus(proxyResult)
	if err != nil {
		return nil, nil, err
	}

	runtime.KeepAlive(obj)

	return newClientPrivateKeyBuf.getData() /* r7 */, newServerPublicKeyBuf.getData() /* r7 */, nil
}

/*
* Updates EnrollmentRecord using server's update token
 */
func (obj *PheClient) UpdateEnrollmentRecord(enrollmentRecord []byte, updateToken []byte) ([]byte, error) {
	newEnrollmentRecordBuf, newEnrollmentRecordBufErr := newBuffer(int(obj.EnrollmentRecordLen() /* lg2 */))
	if newEnrollmentRecordBufErr != nil {
		return nil, newEnrollmentRecordBufErr
	}
	defer newEnrollmentRecordBuf.delete()
	enrollmentRecordData := helperWrapData(enrollmentRecord)
	updateTokenData := helperWrapData(updateToken)

	proxyResult := /*pr4*/ C.vsce_phe_client_update_enrollment_record(obj.cCtx, enrollmentRecordData, updateTokenData, newEnrollmentRecordBuf.ctx)

	err := PheErrorHandleStatus(proxyResult)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(obj)

	return newEnrollmentRecordBuf.getData() /* r7 */, nil
}
