package ratchet

// #include <virgil/crypto/ratchet/vscr_ratchet_public.h>
import "C"


/*
* Class with public constants
*/
type RatchetCommon struct {
}
const (
    /*
    * Max plain text length allowed to be encrypted
    */
    RatchetCommonMaxPlainTextLen uint32 = 30000
    /*
    * Max message length
    */
    RatchetCommonMaxMessageLen uint32 = 32975
    /*
    * Key pair id length
    */
    RatchetCommonKeyIdLen uint32 = 8
    /*
    * Participant id length
    */
    RatchetCommonParticipantIdLen uint32 = 32
    /*
    * Session id length
    */
    RatchetCommonSessionIdLen uint32 = 32
    /*
    * Max number of group chat participants
    */
    RatchetCommonMaxParticipantsCount uint32 = 100
    /*
    * Min number of group chat participants
    */
    RatchetCommonMinParticipantsCount uint32 = 2
    /*
    * Max group message length
    */
    RatchetCommonMaxGroupMessageLen uint32 = 32918
)
