package ratchet

// #include <virgil/crypto/ratchet/vscr_ratchet_public.h>
import "C"
import "runtime"
import foundation "virgil/foundation"
import unsafe "unsafe"


/*
* Ratchet group session.
*/
type RatchetGroupSession struct {
    cCtx *C.vscr_ratchet_group_session_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *RatchetGroupSession) ctx() *C.vscf_impl_t {
    return (*C.vscf_impl_t)(obj.cCtx)
}

func NewRatchetGroupSession() *RatchetGroupSession {
    ctx := C.vscr_ratchet_group_session_new()
    obj := &RatchetGroupSession {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, func (o *RatchetGroupSession) {o.Delete()})
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newRatchetGroupSessionWithCtx(ctx *C.vscr_ratchet_group_session_t /*ct2*/) *RatchetGroupSession {
    obj := &RatchetGroupSession {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, func (o *RatchetGroupSession) {o.Delete()})
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newRatchetGroupSessionCopy(ctx *C.vscr_ratchet_group_session_t /*ct2*/) *RatchetGroupSession {
    obj := &RatchetGroupSession {
        cCtx: C.vscr_ratchet_group_session_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, func (o *RatchetGroupSession) {o.Delete()})
    return obj
}

/*
* Release underlying C context.
*/
func (obj *RatchetGroupSession) Delete() {
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *RatchetGroupSession) delete() {
    C.vscr_ratchet_group_session_delete(obj.cCtx)
}

/*
* Random
*/
func (obj *RatchetGroupSession) SetRng(rng foundation.Random) {
    C.vscr_ratchet_group_session_release_rng(obj.cCtx)
    C.vscr_ratchet_group_session_use_rng(obj.cCtx, (*C.vscf_impl_t)(rng.(context).ctx()))
}

/*
* Shows whether session was initialized.
*/
func (obj *RatchetGroupSession) IsInitialized() bool {
    proxyResult := /*pr4*/C.vscr_ratchet_group_session_is_initialized(obj.cCtx)

    return bool(proxyResult) /* r9 */
}

/*
* Shows whether identity private key was set.
*/
func (obj *RatchetGroupSession) IsPrivateKeySet() bool {
    proxyResult := /*pr4*/C.vscr_ratchet_group_session_is_private_key_set(obj.cCtx)

    return bool(proxyResult) /* r9 */
}

/*
* Shows whether my id was set.
*/
func (obj *RatchetGroupSession) IsMyIdSet() bool {
    proxyResult := /*pr4*/C.vscr_ratchet_group_session_is_my_id_set(obj.cCtx)

    return bool(proxyResult) /* r9 */
}

/*
* Returns current epoch.
*/
func (obj *RatchetGroupSession) GetCurrentEpoch() uint32 {
    proxyResult := /*pr4*/C.vscr_ratchet_group_session_get_current_epoch(obj.cCtx)

    return uint32(proxyResult) /* r9 */
}

/*
* Setups default dependencies:
* - RNG: CTR DRBG
*/
func (obj *RatchetGroupSession) SetupDefaults() error {
    proxyResult := /*pr4*/C.vscr_ratchet_group_session_setup_defaults(obj.cCtx)

    err := RatchetErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}

/*
* Sets identity private key.
*/
func (obj *RatchetGroupSession) SetPrivateKey(myPrivateKey []byte) error {
    myPrivateKeyData := helperWrapData (myPrivateKey)

    proxyResult := /*pr4*/C.vscr_ratchet_group_session_set_private_key(obj.cCtx, myPrivateKeyData)

    err := RatchetErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}

/*
* Sets my id. Should be 32 byte
*/
func (obj *RatchetGroupSession) SetMyId(myId []byte) {
    myIdData := helperWrapData (myId)

    C.vscr_ratchet_group_session_set_my_id(obj.cCtx, myIdData)

    return
}

/*
* Returns my id.
*/
func (obj *RatchetGroupSession) GetMyId() []byte {
    proxyResult := /*pr4*/C.vscr_ratchet_group_session_get_my_id(obj.cCtx)

    return helperExtractData(proxyResult) /* r1 */
}

/*
* Returns session id.
*/
func (obj *RatchetGroupSession) GetSessionId() []byte {
    proxyResult := /*pr4*/C.vscr_ratchet_group_session_get_session_id(obj.cCtx)

    return helperExtractData(proxyResult) /* r1 */
}

/*
* Returns number of participants.
*/
func (obj *RatchetGroupSession) GetParticipantsCount() uint32 {
    proxyResult := /*pr4*/C.vscr_ratchet_group_session_get_participants_count(obj.cCtx)

    return uint32(proxyResult) /* r9 */
}

/*
* Sets up session.
* Use this method when you have newer epoch message and know all participants info.
* NOTE: Identity private key and my id should be set separately.
*/
func (obj *RatchetGroupSession) SetupSessionState(message *RatchetGroupMessage, participants *RatchetGroupParticipantsInfo) error {
    proxyResult := /*pr4*/C.vscr_ratchet_group_session_setup_session_state(obj.cCtx, (*C.vscr_ratchet_group_message_t)(message.ctx()), (*C.vscr_ratchet_group_participants_info_t)(participants.ctx()))

    err := RatchetErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}

/*
* Sets up session.
* Use this method when you have message with next epoch, and you know how participants set was changed.
* NOTE: Identity private key and my id should be set separately.
*/
func (obj *RatchetGroupSession) UpdateSessionState(message *RatchetGroupMessage, addParticipants *RatchetGroupParticipantsInfo, removeParticipants *RatchetGroupParticipantsIds) error {
    proxyResult := /*pr4*/C.vscr_ratchet_group_session_update_session_state(obj.cCtx, (*C.vscr_ratchet_group_message_t)(message.ctx()), (*C.vscr_ratchet_group_participants_info_t)(addParticipants.ctx()), (*C.vscr_ratchet_group_participants_ids_t)(removeParticipants.ctx()))

    err := RatchetErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}

/*
* Encrypts data
*/
func (obj *RatchetGroupSession) Encrypt(plainText []byte) (*RatchetGroupMessage, error) {
    var error C.vscr_error_t
    C.vscr_error_reset(&error)
    plainTextData := helperWrapData (plainText)

    proxyResult := /*pr4*/C.vscr_ratchet_group_session_encrypt(obj.cCtx, plainTextData, &error)

    err := RatchetErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    return newRatchetGroupMessageWithCtx(proxyResult) /* r6 */, nil
}

/*
* Calculates size of buffer sufficient to store decrypted message
*/
func (obj *RatchetGroupSession) DecryptLen(message *RatchetGroupMessage) uint32 {
    proxyResult := /*pr4*/C.vscr_ratchet_group_session_decrypt_len(obj.cCtx, (*C.vscr_ratchet_group_message_t)(message.ctx()))

    return uint32(proxyResult) /* r9 */
}

/*
* Decrypts message
*/
func (obj *RatchetGroupSession) Decrypt(message *RatchetGroupMessage, senderId []byte) ([]byte, error) {
    plainTextBuf, plainTextBufErr := bufferNewBuffer(int(obj.DecryptLen(message) /* lg2 */))
    if plainTextBufErr != nil {
        return nil, plainTextBufErr
    }
    defer plainTextBuf.Delete()
    senderIdData := helperWrapData (senderId)

    proxyResult := /*pr4*/C.vscr_ratchet_group_session_decrypt(obj.cCtx, (*C.vscr_ratchet_group_message_t)(message.ctx()), senderIdData, plainTextBuf.ctx)

    err := RatchetErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return plainTextBuf.getData() /* r7 */, nil
}

/*
* Serializes session to buffer
* NOTE: Session changes its state every encrypt/decrypt operations. Be sure to save it.
*/
func (obj *RatchetGroupSession) Serialize() []byte {
    proxyResult := /*pr4*/C.vscr_ratchet_group_session_serialize(obj.cCtx)

    defer C.vsc_buffer_delete(proxyResult)

    return C.GoBytes(unsafe.Pointer(C.vsc_buffer_bytes(proxyResult)), C.int(C.vsc_buffer_len(proxyResult))) /* r2 */
}

/*
* Deserializes session from buffer.
* NOTE: Deserialized session needs dependencies to be set.
* You should set separately:
* - rng
* - my private key
*/
func RatchetGroupSessionDeserialize(input []byte) (*RatchetGroupSession, error) {
    var error C.vscr_error_t
    C.vscr_error_reset(&error)
    inputData := helperWrapData (input)

    proxyResult := /*pr4*/C.vscr_ratchet_group_session_deserialize(inputData, &error)

    err := RatchetErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    return newRatchetGroupSessionWithCtx(proxyResult) /* r6 */, nil
}

/*
* Creates ticket with new key for adding or removing participants.
*/
func (obj *RatchetGroupSession) CreateGroupTicket() (*RatchetGroupTicket, error) {
    var error C.vscr_error_t
    C.vscr_error_reset(&error)

    proxyResult := /*pr4*/C.vscr_ratchet_group_session_create_group_ticket(obj.cCtx, &error)

    err := RatchetErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    return newRatchetGroupTicketWithCtx(proxyResult) /* r6 */, nil
}
