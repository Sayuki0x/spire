package main

import (
	"github.com/gorilla/websocket"
	uuid "github.com/satori/go.uuid"
	"github.com/vmihailenco/msgpack"
)

///////////////////////////////////////////////////////////////
//
// AUTH MESSAGES
//
///////////////////////////////////////////////////////////////

// Challenge is what initiates a challenge.
type Challenge struct {
	Type           string    `json:"type" msgpack:"type"`
	TransmissionID uuid.UUID `json:"transmissionID" msgpack:"transmissionID"`
	MessageID      uuid.UUID `json:"messageID" msgpack:"messageID"`

	Challenge uuid.UUID `json:"challenge" msgpack:"challenge"`
	PubKey    string    `json:"pubkey" msgpack:"pubkey"`
}

// Response is the response to a challenge.
type Response struct {
	Type           string    `json:"type" msgpack:"type"`
	TransmissionID uuid.UUID `json:"transmissionID" msgpack:"transmissionID"`
	MessageID      uuid.UUID `json:"messageID" msgpack:"messageID"`

	Response string `json:"response" msgpack:"response"`
	PubKey   string `json:"pubkey" msgpack:"pubkey"`
}

///////////////////////////////////////////////////////////////
//
// OUTGOING MESSAGES
//
///////////////////////////////////////////////////////////////

// APISuccess is a general APISuccess message for any operation
type APISuccess struct {
	Type           string    `json:"type" msgpack:"type"`
	TransmissionID uuid.UUID `json:"transmissionID" msgpack:"transmissionID"`
	MessageID      uuid.UUID `json:"messageID" msgpack:"messageID"`

	Data interface{} `json:"data" msgpack:"data"`
}

// APIError is a general error message to be displayed by the client.
type APIError struct {
	Type           string    `json:"type" msgpack:"type"`
	TransmissionID uuid.UUID `json:"transmissionID" msgpack:"transmissionID"`
	MessageID      uuid.UUID `json:"messageID" msgpack:"messageID"`

	Code    string      `json:"code" msgpack:"code"`
	Message string      `json:"message" msgpack:"message"`
	Request interface{} `json:"request" msgpack:"request"`
}

// APIPong is a response to a ping.
type APIPong struct {
	Type           string    `json:"type" msgpack:"type"`
	MessageID      uuid.UUID `json:"messageID" msgpack:"messageID"`
	TransmissionID uuid.UUID `json:"transmissionID" msgpack:"transmissionID"`
}

///////////////////////////////////////////////////////////////
//
// INCOMING MESSAGES
//
///////////////////////////////////////////////////////////////

// BaseReq is a type for websocket messages that pass to and from server and client.
type BaseReq struct {
	Type           string    `json:"type" msgpack:"type"`
	TransmissionID uuid.UUID `json:"transmissionID" msgpack:"transmissionID"`
}

// PermReq is a message from the client to perform operations on channels.
type PermReq struct {
	Type           string    `json:"type" msgpack:"type"`
	TransmissionID uuid.UUID `json:"transmissionID" msgpack:"transmissionID"`

	Method     string `json:"method" msgpack:"method"`
	Permission ChannelPermission
}

// HistoryReq is a history request message.
type HistoryReq struct {
	Type           string    `json:"type" msgpack:"type"`
	TransmissionID uuid.UUID `json:"transmissionID" msgpack:"transmissionID"`

	Method     string    `json:"method" msgpack:"method"`
	ChannelID  uuid.UUID `json:"channelID" msgpack:"channelID"`
	TopMessage uuid.UUID `json:"topMessage" msgpack:"topMessage"`
}

// ChannelReq is a message from the client to perform operations on a channel.
type ChannelReq struct {
	Type           string    `json:"type" msgpack:"type"`
	TransmissionID uuid.UUID `json:"transmissionID" msgpack:"transmissionID"`

	Method    string    `json:"method" msgpack:"method"`
	ChannelID uuid.UUID `json:"channelID" msgpack:"channelID"`
	MessageID uuid.UUID `json:"messageID" msgpack:"messageID"`
	Private   bool      `json:"privateChannel" msgpack:"privateChannel"`
	Name      string    `json:"name" msgpack:"name"`
}

// UserReq is a message to perform operations on users.
type UserReq struct {
	Type           string    `json:"type" msgpack:"type"`
	TransmissionID uuid.UUID `json:"transmissionID" msgpack:"transmissionID"`

	Method     string    `json:"method" msgpack:"method"`
	Username   string    `json:"username" msgpack:"username"`
	Color      string    `json:"color" msgpack:"color"`
	ChannelID  uuid.UUID `json:"channelID" msgpack:"channelID"`
	PowerLevel int       `json:"powerLevel" msgpack:"powerLevel"`
	UserID     uuid.UUID `json:"userID" msgpack:"userID"`
	Avatar     uuid.UUID `json:"avatar" msgpack:"avatar"`
}

// IdentityReq is a message for performing operations on identities.
type IdentityReq struct {
	Type           string    `json:"type" msgpack:"type"`
	Method         string    `json:"method" msgpack:"method"`
	PubKey         string    `json:"pubkey" msgpack:"pubkey"`
	UUID           uuid.UUID `json:"uuid" msgpack:"uuid"`
	Signed         string    `json:"signed" msgpack:"signed"`
	MessageID      uuid.UUID `json:"messageID" msgpack:"messageID"`
	TransmissionID uuid.UUID `json:"transmissionID" msgpack:"transmissionID"`
}

type FileReq struct {
	Type           string    `json:"type" msgpack:"type"`
	File           string    `json:"file" msgpack:"file"`
	FileID         string    `json:"fileID" msgpack:"fileID"`
	TransmissionID uuid.UUID `json:"transmissionID" msgpack:"transmissionID"`
	ChannelID      uuid.UUID `json:"channelID" msgpack:"channelID"`
	Method         string    `json:"method" msgpack:"method"`
	Filename       string    `json:"filename" msgpack:"filename"`
}

///////////////////////////////////////////////////////////////
//
// PUSH MESSAGES
//
///////////////////////////////////////////////////////////////

type PowerLevelPush struct {
	Type           string        `json:"type" msgpack:"type"`
	MessageID      uuid.UUID     `json:"messageID" msgpack:"messageID"`
	TransmissionID uuid.UUID     `json:"transmissionID" msgpack:"transmissionID"`
	PowerLevels    RequiredPower `json:"powerLevels" msgpack:"powerLevels"`
}

// ChannelListPush is a message with a list of the user's permissioned channels.
type ChannelListPush struct {
	Type           string    `json:"type" msgpack:"type"`
	MessageID      uuid.UUID `json:"messageID" msgpack:"messageID"`
	TransmissionID uuid.UUID `json:"transmissionID" msgpack:"transmissionID"`
	Channels       []Channel `json:"data" msgpack:"data"`
}

// ClientPush is a message to the client with their login info
type ClientPush struct {
	Type           string    `json:"type" msgpack:"type"`
	MessageID      uuid.UUID `json:"messageID" msgpack:"messageID"`
	TransmissionID uuid.UUID `json:"transmissionID" msgpack:"transmissionID"`
	Client         *Client   `json:"client" msgpack:"client"`
}

func sendMessage(msg interface{}, conn *websocket.Conn) {
	msgpMsg, err := msgpack.Marshal(msg)
	check(err)
	conn.WriteMessage(2, msgpMsg)
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
