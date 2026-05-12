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
    MsgTypeRegular MsgType = 1
    /*
    * Prekey message. This message is sent by initiator till first response is received.
    */
    MsgTypePrekey MsgType = 2
)
