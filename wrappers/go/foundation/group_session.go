package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import "runtime"


/*
* Group chat encryption session.
*/
type GroupSession struct {
    cCtx *C.vscf_group_session_t /*ct2*/
}
const (
    /*
    * Sender id len
    */
    GroupSessionSenderIdLen uint32 = 32
    /*
    * Max plain text len
    */
    GroupSessionMaxPlainTextLen uint32 = 30000
    /*
    * Max epochs count
    */
    GroupSessionMaxEpochsCount uint32 = 50
    /*
    * Salt size
    */
    GroupSessionSaltSize uint32 = 32
)

/* Handle underlying C context. */
func (obj *GroupSession) ctx() *C.vscf_impl_t {
    return (*C.vscf_impl_t)(obj.cCtx)
}

func NewGroupSession() *GroupSession {
    ctx := C.vscf_group_session_new()
    obj := &GroupSession {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, func (o *GroupSession) {o.Delete()})
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newGroupSessionWithCtx(ctx *C.vscf_group_session_t /*ct2*/) *GroupSession {
    obj := &GroupSession {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, func (o *GroupSession) {o.Delete()})
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newGroupSessionCopy(ctx *C.vscf_group_session_t /*ct2*/) *GroupSession {
    obj := &GroupSession {
        cCtx: C.vscf_group_session_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, func (o *GroupSession) {o.Delete()})
    return obj
}

/*
* Release underlying C context.
*/
func (obj *GroupSession) Delete() {
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *GroupSession) delete() {
    C.vscf_group_session_delete(obj.cCtx)
}

/*
* Random
*/
func (obj *GroupSession) SetRng(rng Random) {
    C.vscf_group_session_release_rng(obj.cCtx)
    C.vscf_group_session_use_rng(obj.cCtx, (*C.vscf_impl_t)(rng.ctx()))
}

/*
* Returns current epoch.
*/
func (obj *GroupSession) GetCurrentEpoch() uint32 {
    proxyResult := /*pr4*/C.vscf_group_session_get_current_epoch(obj.cCtx)

    return uint32(proxyResult) /* r9 */
}

/*
* Setups default dependencies:
* - RNG: CTR DRBG
*/
func (obj *GroupSession) SetupDefaults() error {
    proxyResult := /*pr4*/C.vscf_group_session_setup_defaults(obj.cCtx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}

/*
* Returns session id.
*/
func (obj *GroupSession) GetSessionId() []byte {
    proxyResult := /*pr4*/C.vscf_group_session_get_session_id(obj.cCtx)

    return helperExtractData(proxyResult) /* r1 */
}

/*
* Adds epoch. New epoch should be generated for member removal or proactive to rotate encryption key.
* Epoch message should be encrypted and signed by trusted group chat member (admin).
*/
func (obj *GroupSession) AddEpoch(message *GroupSessionMessage) error {
    proxyResult := /*pr4*/C.vscf_group_session_add_epoch(obj.cCtx, (*C.vscf_group_session_message_t)(message.ctx()))

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}

/*
* Encrypts data
*/
func (obj *GroupSession) Encrypt(plainText []byte, privateKey PrivateKey) (*GroupSessionMessage, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)
    plainTextData := helperWrapData (plainText)

    proxyResult := /*pr4*/C.vscf_group_session_encrypt(obj.cCtx, plainTextData, (*C.vscf_impl_t)(privateKey.ctx()), &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    return newGroupSessionMessageWithCtx(proxyResult) /* r6 */, nil
}

/*
* Calculates size of buffer sufficient to store decrypted message
*/
func (obj *GroupSession) DecryptLen(message *GroupSessionMessage) uint32 {
    proxyResult := /*pr4*/C.vscf_group_session_decrypt_len(obj.cCtx, (*C.vscf_group_session_message_t)(message.ctx()))

    return uint32(proxyResult) /* r9 */
}

/*
* Decrypts message
*/
func (obj *GroupSession) Decrypt(message *GroupSessionMessage, publicKey PublicKey) ([]byte, error) {
    plainTextBuf, plainTextBufErr := bufferNewBuffer(int(obj.DecryptLen(message) /* lg2 */))
    if plainTextBufErr != nil {
        return nil, plainTextBufErr
    }
    defer plainTextBuf.Delete()


    proxyResult := /*pr4*/C.vscf_group_session_decrypt(obj.cCtx, (*C.vscf_group_session_message_t)(message.ctx()), (*C.vscf_impl_t)(publicKey.ctx()), plainTextBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return plainTextBuf.getData() /* r7 */, nil
}

/*
* Creates ticket with new key for removing participants or proactive to rotate encryption key.
*/
func (obj *GroupSession) CreateGroupTicket() (*GroupSessionTicket, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_group_session_create_group_ticket(obj.cCtx, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    return newGroupSessionTicketWithCtx(proxyResult) /* r6 */, nil
}
