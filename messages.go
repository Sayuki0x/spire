package main

import (
	"encoding/json"

	"github.com/gorilla/websocket"
	uuid "github.com/satori/go.uuid"
)

///////////////////////////////////////////////////////////////
//
// AUTH MESSAGES
//
///////////////////////////////////////////////////////////////

// Challenge is what initiates a challenge.
type Challenge struct {
	Type           string    `json:"type"`
	TransmissionID uuid.UUID `json:"transmissionID"`
	MessageID      uuid.UUID `json:"messageID"`

	Challenge uuid.UUID `json:"challenge"`
	PubKey    string    `json:"pubkey"`
}

// Response is the response to a challenge.
type Response struct {
	Type           string    `json:"type"`
	TransmissionID uuid.UUID `json:"transmissionID"`
	MessageID      uuid.UUID `json:"messageID"`

	Response string `json:"response"`
	PubKey   string `json:"pubkey"`
}

///////////////////////////////////////////////////////////////
//
// OUTGOING MESSAGES
//
///////////////////////////////////////////////////////////////

// APISuccess is a general APISuccess message for any operation
type APISuccess struct {
	Type           string    `json:"type"`
	TransmissionID uuid.UUID `json:"transmissionID"`
	MessageID      uuid.UUID `json:"messageID"`

	Data interface{} `json:"data"`
}

// APIError is a general error message to be displayed by the client.
type APIError struct {
	Type           string    `json:"type"`
	TransmissionID uuid.UUID `json:"transmissionID"`
	MessageID      uuid.UUID `json:"messageID"`

	Code    string      `json:"code"`
	Message string      `json:"message"`
	Request interface{} `json:"request"`
}

// APIPong is a response to a ping.
type APIPong struct {
	Type           string    `json:"type"`
	MessageID      uuid.UUID `json:"messageID"`
	TransmissionID uuid.UUID `json:"transmissionID"`
}

///////////////////////////////////////////////////////////////
//
// INCOMING MESSAGES
//
///////////////////////////////////////////////////////////////

// BaseReq is a type for websocket messages that pass to and from server and client.
type BaseReq struct {
	Type           string    `json:"type"`
	TransmissionID uuid.UUID `json:"transmissionID"`
}

// PermReq is a message from the client to perform operations on channels.
type PermReq struct {
	Type           string    `json:"type"`
	TransmissionID uuid.UUID `json:"transmissionID"`

	Method     string `json:"method"`
	Permission ChannelPermission
}

// HistoryReq is a history request message.
type HistoryReq struct {
	Type           string    `json:"type"`
	TransmissionID uuid.UUID `json:"transmissionID"`

	Method     string    `json:"method"`
	ChannelID  uuid.UUID `json:"channelID"`
	TopMessage uuid.UUID `json:"topMessage"`
}

// ChannelReq is a message from the client to perform operations on a channel.
type ChannelReq struct {
	Type           string    `json:"type"`
	TransmissionID uuid.UUID `json:"transmissionID"`

	Method    string    `json:"method"`
	ChannelID uuid.UUID `json:"channelID"`
	MessageID uuid.UUID `json:"messageID"`
	Private   bool      `json:"privateChannel"`
	Name      string    `json:"name"`
}

// UserReq is a message to perform operations on users.
type UserReq struct {
	Type           string    `json:"type"`
	TransmissionID uuid.UUID `json:"transmissionID"`

	Method     string    `json:"method"`
	Username   string    `json:"username"`
	ChannelID  uuid.UUID `json:"channelID"`
	PowerLevel int       `json:"powerLevel"`
	UserID     uuid.UUID `json:"userID"`
}

// IdentityReq is a message for performing operations on identities.
type IdentityReq struct {
	Type           string    `json:"type"`
	Method         string    `json:"method"`
	PubKey         string    `json:"pubkey"`
	UUID           uuid.UUID `json:"uuid"`
	Signed         string    `json:"signed"`
	MessageID      uuid.UUID `json:"messageID"`
	TransmissionID uuid.UUID `json:"transmissionID"`
}

///////////////////////////////////////////////////////////////
//
// PUSH MESSAGES
//
///////////////////////////////////////////////////////////////

// ChannelListPush is a message with a list of the user's permissioned channels.
type ChannelListPush struct {
	Type           string    `json:"type"`
	MessageID      uuid.UUID `json:"messageID"`
	TransmissionID uuid.UUID `json:"transmissionID"`
	Channels       []Channel `json:"data"`
}

// ClientPush is a message to the client with their login info
type ClientPush struct {
	Type           string    `json:"type"`
	MessageID      uuid.UUID `json:"messageID"`
	TransmissionID uuid.UUID `json:"transmissionID"`
	Client         Client    `json:"client"`
}

func sendMessage(msg interface{}, conn *websocket.Conn) {
	jsonMessage, _ := json.Marshal(msg)
	log.Debug("OUT", string(jsonMessage))

	conn.WriteJSON(msg)
}

func sendError(code string, message string, conn *websocket.Conn, transmissionID uuid.UUID, request interface{}) {
	err := APIError{
		Type:           "error",
		MessageID:      uuid.NewV4(),
		TransmissionID: transmissionID,
		Message:        message,
		Code:           code,
		Request:        request,
	}
	sendMessage(err, conn)
}

func sendSuccess(conn *websocket.Conn, transmissionID uuid.UUID, Data interface{}) {
	success := APISuccess{
		Type:           "success",
		MessageID:      uuid.NewV4(),
		TransmissionID: transmissionID,
		Data:           Data,
	}
	sendMessage(success, conn)
}
