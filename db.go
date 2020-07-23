package main

import (
	"time"

	"github.com/jinzhu/gorm"
	uuid "github.com/satori/go.uuid"
)

// Model that hides unnecessary fields in json
type Model struct {
	ID        uint       `json:"index" msgpack:"index" gorm:"primary_key"`
	CreatedAt time.Time  `json:"-" msgpack:"-"`
	UpdatedAt time.Time  `json:"-" msgpack:"-"`
	DeletedAt *time.Time `json:"-" msgpack:"-" sql:"index"`
}

// Files are uploaded files
type File struct {
	Model
	FileID    uuid.UUID `json:"fileID" msgpack:"fileID"`
	FileName  string    `json:"fileName" msgpack:"fileName"`
	ChannelID uuid.UUID `json:"channelID" msgpack:"channelID"`
	OwnerID   uuid.UUID `json:"ownerID" msgpack:"ownerID"`
}

// ChatModel is similar to Model but shows createdAt key
type ChatModel struct {
	ID        uint       `json:"index" msgpack:"index" gorm:"primary_key"`
	CreatedAt time.Time  `json:"createdAt" msgpack:"createdAt"`
	UpdatedAt time.Time  `json:"-" msgpack:"-"`
	DeletedAt *time.Time `json:"-" msgpack:"-" sql:"index"`
}

// ChannelPermission database entry
type ChannelPermission struct {
	Model
	UserID     uuid.UUID `json:"userID" msgpack:"userID"`
	ChannelID  uuid.UUID `json:"channelID" msgpack:"channelID"`
	PowerLevel int       `json:"powerLevel" msgpack:"powerLevel"`
}

// Client database entry.
type Client struct {
	Model
	PubKey     string    `json:"pubkey" msgpack:"pubkey"`
	Username   string    `json:"username" msgpack:"username"`
	PowerLevel int       `json:"powerLevel" msgpack:"powerLevel"`
	UserID     uuid.UUID `json:"userID" msgpack:"userID"`
	Banned     bool      `json:"banned" msgpack:"banned"`
	Avatar     uuid.UUID `json:"avatar" msgpack:"avatar"`
	Color      string    `json:"color" msgpack:"color"`
}

// Channel database entry
type Channel struct {
	Model
	ChannelID uuid.UUID `json:"channelID" msgpack:"channelID"`
	Admin     uuid.UUID `json:"admin" msgpack:"admin"`
	Public    bool      `json:"public" msgpack:"public"`
	Name      string    `json:"name" msgpack:"name"`
}

// ChatMessage is the messages database entry
type ChatMessage struct {
	ChatModel
	UserID         uuid.UUID `json:"userID" msgpack:"userID"`
	Username       string    `json:"username" msgpack:"username"`
	MessageID      uuid.UUID `json:"messageID" msgpack:"messageID"`
	TransmissionID uuid.UUID `json:"transmissionID" msgpack:"transmissionID"`
	Method         string    `json:"method" msgpack:"method"`
	Message        string    `json:"message" msgpack:"method"`
	ChannelID      uuid.UUID `json:"channelID" msgpack:"channelID"`
	Type           string    `json:"type" msgpack:"type"`
	Author         Client    `json:"author" msgpack:"author"`
}

// Dump of all data for import by another server
type Dump struct {
	Clients            []Client            `json:"clients" msgpack:"clients"`
	Channels           []Channel           `json:"channels" msgpack:"channels"`
	ChannelPermissions []ChannelPermission `json:"channelPermissions" msgpack:"channelPermissions"`
	Chats              []ChatMessage       `json:"chat" msgpack:"chat"`
	Files              []File              `json:"files" msgpack:"files"`
}

// StatusRes is the status http api endpoing response.
type StatusRes struct {
	Version   string `json:"version"`
	Status    string `json:"status"`
	MessageID string `json:"messageID"`
	PublicKey string `json:"publicKey"`
}

func getDB(config Config) *gorm.DB {
	// initialize database, support sqlite and mysql
	db, err := gorm.Open(config.DbType, config.DbConnectionStr)
	check(err)

	db.AutoMigrate(&Client{})
	db.AutoMigrate(&Channel{})
	db.AutoMigrate(&ChatMessage{})
	db.AutoMigrate(&ChannelPermission{})
	db.AutoMigrate(&File{})

	if config.DbType == "mysql" {
		db.Model(&ChatMessage{}).ModifyColumn("message", "varchar(2000)")
	}

	return db
}
