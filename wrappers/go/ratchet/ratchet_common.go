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
    RatchetCommonMaxPlainTextLen int = 30000
    /*
    * Max message length
    */
    RatchetCommonMaxMessageLen int = 32975
    /*
    * Key pair id length
    */
    RatchetCommonKeyIdLen int = 8
    /*
    * Participant id length
    */
    RatchetCommonParticipantIdLen int = 32
    /*
    * Session id length
    */
    RatchetCommonSessionIdLen int = 32
    /*
    * Max number of group chat participants
    */
    RatchetCommonMaxParticipantsCount int = 100
    /*
    * Min number of group chat participants
    */
    RatchetCommonMinParticipantsCount int = 2
    /*
    * Max group message length
    */
    RatchetCommonMaxGroupMessageLen int = 32918
)
