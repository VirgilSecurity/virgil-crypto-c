package ratchet

import "C"

/*
* Represents message type
*/
type MsgType int
const (
    /*
    * Regular message. This message is used all the time except case described in prekey message section.
    */
    MSG_TYPE_REGULAR MsgType = 1
    /*
    * Prekey message. This message is sent by initiator till first response is received.
    */
    MSG_TYPE_PREKEY MsgType = 2
)
