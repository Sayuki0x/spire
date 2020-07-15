package main

import (
	"time"

	"github.com/jinzhu/gorm"
	uuid "github.com/satori/go.uuid"
)

// Model that hides unnecessary fields in json
type Model struct {
	ID        uint       `json:"index" gorm:"primary_key"`
	CreatedAt time.Time  `json:"-"`
	UpdatedAt time.Time  `json:"-"`
	DeletedAt *time.Time `json:"-" sql:"index"`
}

// Files are uploaded files
type File struct {
	Model
	FileID    uuid.UUID `json:"fileID"`
	FileName  string    `json:"fileName"`
	ChannelID uuid.UUID `json:"channelID"`
	OwnerID   uuid.UUID `json:"ownerID"`
}

// ChatModel is similar to Model but shows createdAt key
type ChatModel struct {
	ID        uint       `json:"index" gorm:"primary_key"`
	CreatedAt time.Time  `json:"createdAt"`
	UpdatedAt time.Time  `json:"-"`
	DeletedAt *time.Time `json:"-" sql:"index"`
}

// ChannelPermission database entry
type ChannelPermission struct {
	Model
	UserID     uuid.UUID `json:"userID"`
	ChannelID  uuid.UUID `json:"channelID"`
	PowerLevel int       `json:"powerLevel"`
}

// Client database entry.
type Client struct {
	Model
	PubKey     string    `json:"pubkey"`
	Username   string    `json:"username"`
	PowerLevel int       `json:"powerLevel"`
	UserID     uuid.UUID `json:"userID"`
	Banned     bool      `json:"banned"`
}

// Channel database entry
type Channel struct {
	Model
	ChannelID uuid.UUID `json:"channelID"`
	Admin     uuid.UUID `json:"admin"`
	Public    bool      `json:"public"`
	Name      string    `json:"name"`
}

// ChatMessage is the messages database entry
type ChatMessage struct {
	ChatModel
	UserID         uuid.UUID `json:"userID"`
	Username       string    `json:"username"`
	MessageID      uuid.UUID `json:"messageID"`
	TransmissionID uuid.UUID `json:"transmissionID"`
	Method         string    `json:"method"`
	Message        string    `json:"message"`
	ChannelID      uuid.UUID `json:"channelID"`
	Type           string    `json:"type"`
}

// Dump of all data for import by another server
type Dump struct {
	Clients            []Client            `json:"clients"`
	Channels           []Channel           `json:"channels"`
	ChannelPermissions []ChannelPermission `json:"channelPermissions"`
	Chats              []ChatMessage       `json:"chat"`
	Files              []File              `json:"files"`
}

// StatusRes is the status http api endpoing response.
type StatusRes struct {
	Version   string `json:"versiofn"`
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

	db.Model(&ChatMessage{}).ModifyColumn("message", "varchar(2000)")

	return db
}
