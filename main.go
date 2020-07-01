package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"golang.org/x/crypto/ed25519"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"github.com/op/go-logging"
	uuid "github.com/satori/go.uuid"
)

var wsClients = []*websocket.Conn{}
var channelSubs = []*ChannelSub{}

const version string = "0.4.1"
const emptyUserID = "00000000-0000-0000-0000-000000000000"

type Model struct {
	ID        uint       `json:"index" gorm:"primary_key"`
	CreatedAt time.Time  `json:"-"`
	UpdatedAt time.Time  `json:"-"`
	DeletedAt *time.Time `json:"-" sql:"index"`
}

type ChannelPermission struct {
	gorm.Model
	UserID     uuid.UUID `json:"userID"`
	ChannelID  uuid.UUID `json:"channelID"`
	PowerLevel int       `json:"powerLevel"`
}

type ClientInfo struct {
	Type   string `json:"type"`
	Client Client `json:"client"`
}

type UserInfoMsg struct {
	MessageID uuid.UUID `json:"messageID"`
	Type      string    `json:"type"`
	Method    string    `json:"method"`
	Username  string    `json:"username"`
	UserTag   string    `json:"userTag"`
}

type UserInfoRes struct {
	MessageID uuid.UUID `json:"messageID"`
	Type      string    `json:"type"`
	Method    string    `json:"method"`
	MatchList []Client  `json:"matchList"`
}

type ChannelPermMsg struct {
	MessageID  uuid.UUID `json:"messageID"`
	Type       string    `json:"type"`
	Method     string    `json:"method"`
	Permission ChannelPermission
}

type WelcomeMessage struct {
	MessageID uuid.UUID `json:"messageID"`
	Type      string    `json:"type"`
	Message   string    `json:"message"`
}

type PongMessage struct {
	MessageID uuid.UUID `json:"messageID"`
	Type      string    `json:"type"`
}

type HistoryReqMessage struct {
	Type       string    `json:"type"`
	ChannelID  uuid.UUID `json:"channelID"`
	MessageID  uuid.UUID `json:"messageID"`
	Method     string    `json:"method"`
	TopMessage uuid.UUID `json:"topMessage"`
}

type ChatMessage struct {
	Model
	UserID    uuid.UUID `json:"userID"`
	Username  string    `json:"username"`
	MessageID uuid.UUID `json:"messageID"`
	Method    string    `json:"method"`
	Message   string    `json:"message"`
	ChannelID uuid.UUID `json:"channelID"`
	Type      string    `json:"type"`
}

type Client struct {
	Model
	PubKey     string    `json:"pubkey"`
	Username   string    `json:"username"`
	PowerLevel int       `json:"powerLevel"`
	UserID     uuid.UUID `json:"userID"`
	Banned     bool      `json:"banned"`
}

type Channel struct {
	Model
	ChannelID uuid.UUID `json:"channelID"`
	Admin     uuid.UUID `json:"admin"`
	Public    bool      `json:"public"`
	Name      string    `json:"name"`
}

type ChannelMessage struct {
	Type      string    `json:"type"`
	Method    string    `json:"method"`
	ChannelID uuid.UUID `json:"channelID"`
	MessageID uuid.UUID `json:"messageID"`
	Private   bool      `json:"privateChannel"`
	Name      string    `json:"name"`
}

type ChannelResponse struct {
	Type      string    `json:"type"`
	Method    string    `json:"method"`
	Status    string    `json:"status"`
	ChannelID uuid.UUID `json:"channelID"`
	Name      string    `json:"name"`
}

type AuthResultMessage struct {
	Type      string    `json:"type"`
	Status    string    `json:"status"`
	MessageID uuid.UUID `json:"messageID"`
}

type ChannelList struct {
	MessageID uuid.UUID `json:"messageID"`
	Type      string    `json:"type"`
	Method    string    `json:"method"`
	Status    string    `json:"status"`
	Channels  []Channel `json:"channels"`
}

type UserMessage struct {
	Type       string    `json:"type"`
	Method     string    `json:"method"`
	Username   string    `json:"username"`
	ChannelID  uuid.UUID `json:"channelID"`
	PowerLevel int       `json:"powerLevel"`
	UserID     uuid.UUID `json:"userID"`
}

// Message is a type for websocket messages that pass to and from server and client.
type Message struct {
	Type      string    `json:"type"`
	MessageID uuid.UUID `json:"messageID"`
}

type SuccessMessage struct {
	Type      string    `json:"type"`
	MessageID uuid.UUID `json:"messageID"`
	Status    string    `json:"status"`
}

type InfoMessage struct {
	Type      string    `json:"type"`
	MessageID uuid.UUID `json:"messageID"`
	Message   string    `json:"message"`
}

type ChannelSub struct {
	UserID     uuid.UUID       `json:"userID"`
	ChannelID  uuid.UUID       `json:"channelID"`
	Connection *websocket.Conn `json:"-"`
}

type ChallengeSub struct {
	PubKey    string    `json:"pubkey"`
	MessageID uuid.UUID `json:"messageID"`
}

type ChallengeMessage struct {
	Type      string    `json:"type"`
	MessageID uuid.UUID `json:"messageID"`
	PubKey    string    `json:"pubkey"`
}

type ChallengeResponse struct {
	Type      string    `json:"type"`
	MessageID uuid.UUID `json:"messageID"`
	Response  string    `json:"response"`
	PubKey    string    `json:"pubkey"`
}

type IdentityMessage struct {
	Type      string    `json:"type"`
	Method    string    `json:"method"`
	PubKey    string    `json:"pubkey"`
	UUID      uuid.UUID `json:"uuid"`
	Signed    string    `json:"signed"`
	MessageID uuid.UUID `json:"messageID"`
}

type IdentityResponse struct {
	Method    string    `json:"method"`
	Type      string    `json:"type"`
	MessageID uuid.UUID `json:"messageID"`
	UUID      uuid.UUID `json:"uuid"`
	Status    string    `json:"status"`
}

type ErrorMessage struct {
	Type    string `json:"type"`
	Code    string `json:"code"`
	Message string `json:"message"`
	Error   error  `json:"error"`
}

// KeyPair is a type that contains a Public and private ed25519 key.
type KeyPair struct {
	Pub  ed25519.PublicKey
	Priv ed25519.PrivateKey
}

// App is the main app.
type App struct {
	Router *mux.Router
	Db     *gorm.DB
	Log    *logging.Logger
}

func printAscii(log *logging.Logger) {
	fmt.Printf("\033[35mvvvvvvv           vvvvvvv    eeeeeeeeeeee    xxxxxxx      xxxxxxx\n" +
		" v:::::v         v:::::v   ee::::::::::::ee   x:::::x    x:::::x \n" +
		"  v:::::v       v:::::v   e::::::eeeee:::::ee  x:::::x  x:::::x  \n" +
		"   v:::::v     v:::::v   e::::::e     e:::::e   x:::::xx:::::x   \n" +
		"    v:::::v   v:::::v    e:::::::eeeee::::::e    x::::::::::x    \n" +
		"     v:::::v v:::::v     e:::::::::::::::::e      x::::::::x     \n" +
		"      v:::::v:::::v      e::::::eeeeeeeeeee       x::::::::x     \n" +
		"       v:::::::::v       e:::::::e               x::::::::::x    \n" +
		"        v:::::::v        e::::::::e             x:::::xx:::::x   \n" +
		"         v:::::v          e::::::::eeeeeeee    x:::::x  x:::::x  \n" +
		"          v:::v            ee:::::::::::::e   x:::::x    x:::::x \n" +
		"           vvv               eeeeeeeeeeeeee  xxxxxxx      xxxxxxx\033[37m\n\n")
	log.Info("Vex version number " + version)
	log.Info("© 2020 LogicBite LLC")
	log.Info("See included LICENSE for details")
}

func checkConfig(log *logging.Logger) {
	_, configErr := os.Stat("config")
	if os.IsNotExist(configErr) {
		log.Debug("Creating configuration folder.")
		os.Mkdir("config", 0700)
	}
	_, pubKeyErr := os.Stat("config/key.pub")
	_, privKeyErr := os.Stat("config/key.priv")
	if os.IsNotExist(privKeyErr) && os.IsNotExist(pubKeyErr) {
		createKeyFiles(log)
	}
}

func createKeyFiles(log *logging.Logger) {
	log.Debug("Creating keyfiles.")
	_, pubKeyErr := os.Stat("config/key.pub")
	if os.IsNotExist(pubKeyErr) {
		os.Create("config/key.pub")
	}
	_, privKeyErr := os.Stat("config/key.priv")
	if os.IsNotExist(privKeyErr) {
		os.Create("config/key.priv")
	}

	keys := generateKeys()

	writeBytesToFile("config/key.pub", keys.Pub, log)
	writeBytesToFile("config/key.priv", keys.Priv, log)
}

func checkKeys(log *logging.Logger) KeyPair {
	_, pubKeyErr := os.Stat("config/key.pub")
	_, privKeyErr := os.Stat("config/key.priv")
	if os.IsNotExist(pubKeyErr) && os.IsNotExist(privKeyErr) {
		createKeyFiles(log)
	}

	var keys KeyPair

	keys.Pub = readBytesFromFile("config/key.pub", log)
	keys.Priv = readBytesFromFile("config/key.priv", log)

	log.Info("Server Public key " + hex.EncodeToString(keys.Pub))

	return keys
}

// Initialize does the initialization of App.
func (a *App) Initialize() {
	//initialize logger
	var log = logging.MustGetLogger("vex")
	var format = logging.MustStringFormatter(
		`%{color}%{time:15:04:05.000} ▶ %{level:.4s}%{color:reset} %{message}`,
	)
	backend := logging.NewLogBackend(os.Stderr, "", 0)
	backendFormatter := logging.NewBackendFormatter(backend, format)
	logging.SetBackend(backendFormatter)

	printAscii(log)

	// initialize configuration files
	checkConfig(log)
	var keys = checkKeys(log)

	// initialize database
	db, err := gorm.Open("sqlite3", "vex-server.db")
	if err != nil {
		log.Error("Failed to connect to database.")
		os.Exit(1)
	}
	db.AutoMigrate(&Client{})
	db.AutoMigrate(&Channel{})
	db.AutoMigrate(&ChatMessage{})
	db.AutoMigrate(&ChannelPermission{})
	a.Db = db

	// initialize router
	router := mux.NewRouter()
	router.Handle("/socket", SocketHandler(keys, db, log)).Methods("GET")
	a.Router = router
}

func generateKeys() KeyPair {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal("Something went wrong generating the keys.")
	}

	var keys KeyPair

	keys.Pub = pub
	keys.Priv = priv

	return keys
}

func sendChannelList(conn *websocket.Conn, db *gorm.DB, log *logging.Logger, clientInfo Client) {
	channels := []Channel{}

	db.Where("public = ?", true).Find(&channels)

	channelPerms := []ChannelPermission{}

	db.Where("user_id = ?", clientInfo.UserID).Find(&channelPerms)

	for _, perm := range channelPerms {
		var privChannel Channel
		db.First(&privChannel, "channel_id = ?", perm.ChannelID)
		if privChannel.ID != 0 {
			channels = append(channels, privChannel)
		}
	}

	orderedChannels := []Channel{}

	for i, channel := range channels {
		channel.ID = uint(i + 1)
		orderedChannels = append(orderedChannels, channel)
	}

	var channelList ChannelList

	channelList.MessageID = uuid.NewV4()
	channelList.Type = "channelListResponse"
	channelList.Status = "SUCCESS"
	channelList.Method = "RETRIEVE"
	channelList.Channels = orderedChannels

	log.Debug("OUT", channelList)
	conn.WriteJSON(channelList)
}

func readBytesFromFile(filename string, log *logging.Logger) []byte {
	// Open file for reading
	file, openErr := os.Open(filename)
	if openErr != nil {
		log.Fatal(openErr)
	}

	data, readErr := ioutil.ReadAll(file)
	if readErr != nil {
		log.Fatal(readErr)
	}

	bytes, _ := hex.DecodeString(string(data))

	return bytes
}

func writeBytesToFile(filename string, bytes []byte, log *logging.Logger) bool {
	file, openErr := os.OpenFile(filename, os.O_RDWR, 0700)
	if openErr != nil {
		log.Fatal("Error opening file " + filename + " for writing.")
		log.Fatal(openErr)
		return false
	}
	file.Write([]byte(hex.EncodeToString(bytes)))
	syncErr := file.Sync()
	if syncErr != nil {
		log.Fatal(syncErr)
		return false
	}
	file.Close()
	return true
}

func main() {
	a := App{}
	a.Initialize()
	a.Run(":8000")
}

func killUnauthedConnection(authed *bool, conn *websocket.Conn) {
	timer := time.NewTimer(3 * time.Second)
	<-timer.C

	if !*authed {
		conn.Close()
	}
}

// SocketHandler handles the websocket connection messages and responses.
func SocketHandler(keys KeyPair, db *gorm.DB, log *logging.Logger) http.Handler {
	return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {

		var upgrader = websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
		}

		upgrader.CheckOrigin = func(req *http.Request) bool { return true }

		conn, _ := upgrader.Upgrade(res, req, nil)
		log.Notice("Incoming websocket connection.")

		challengeSubscriptions := []ChallengeSub{}
		joinedChannelIDs := []uuid.UUID{}

		authed := false
		go killUnauthedConnection(&authed, conn)

		var clientInfo Client

		for {
			_, msg, err := conn.ReadMessage()

			if err != nil {
				scanComplete := false
				log.Warning("Websocket connection terminated. Removing subscriptions.")
				deletedIds := []uuid.UUID{}
				for true {
					if len(channelSubs) == 0 {
						break
					}
					for i, sb := range channelSubs {
						if sb.UserID == clientInfo.UserID && sb.Connection == conn {
							deletedIds = append(deletedIds, sb.ChannelID)
							channelSubs = append(channelSubs[:i], channelSubs[i+1:]...)
							break
						}

						if i == len(channelSubs)-1 {
							scanComplete = true
						}
					}
					if scanComplete {
						break
					}
				}

				log.Debug("Subscriptions removed for " + clientInfo.UserID.String())
				return
			}

			var message Message
			json.Unmarshal(msg, &message)

			if message.Type == "" {
				log.Warning("Invalid message: " + string(msg))
				continue
			}

			log.Debug("IN", string(msg))

			switch message.Type {
			case "user":
				if !authed {
					log.Warning("Not authorized!")
					conn.Close()
					break
				}

				var userMessage UserMessage
				json.Unmarshal(msg, &userMessage)

				if userMessage.Method == "BAN" {
					if clientInfo.PowerLevel < 50 {
						permError := ErrorMessage{
							Type:    "error",
							Message: "You don't have a high enough power level.",
							Code:    "PWRLVL",
						}
						log.Debug("OUT", permError)
						conn.WriteJSON(permError)
						break
					}

					var bannedUser Client
					db.First(&bannedUser, "user_id = ?", userMessage.UserID)

					if bannedUser.ID == 0 {
						log.Warning("Requested ban to user that does not exist.")
						break
					}

					bannedUser.Banned = true
					db.Save(&bannedUser)

					for _, sub := range channelSubs {
						if sub.UserID == userMessage.UserID {
							kickErr := ErrorMessage{
								Type:    "error",
								Code:    "BANNED",
								Message: "You have been banned.",
							}
							log.Debug("OUT", kickErr)
							sub.Connection.WriteJSON(kickErr)
							timer := time.NewTimer(100 * time.Millisecond)
							<-timer.C
							sub.Connection.Close()
						}
					}
					log.Notice("Banned user " + userMessage.UserID.String())
					kickSuccessMsg := InfoMessage{
						Type:      "serverMessage",
						MessageID: uuid.NewV4(),
						Message:   "You have banned user " + userMessage.UserID.String(),
					}
					conn.WriteJSON(kickSuccessMsg)
				}

				if userMessage.Method == "KICK" {
					if clientInfo.PowerLevel < 50 {
						permError := ErrorMessage{
							Type:    "error",
							Message: "You don't have a high enough power level.",
						}
						log.Debug("OUT", permError)
						conn.WriteJSON(permError)
						break
					}

					for _, sub := range channelSubs {
						if sub.UserID == userMessage.UserID {
							kickErr := ErrorMessage{
								Type:    "error",
								Code:    "KICKED",
								Message: "You have been kicked.",
							}
							log.Debug("OUT", kickErr)
							sub.Connection.WriteJSON(kickErr)
							timer := time.NewTimer(100 * time.Millisecond)
							<-timer.C
							sub.Connection.Close()
						}
					}
					log.Notice("Kicked user " + userMessage.UserID.String())
					kickSuccessMsg := InfoMessage{
						Type:      "serverMessage",
						MessageID: uuid.NewV4(),
						Message:   "You have kicked user " + userMessage.UserID.String(),
					}
					conn.WriteJSON(kickSuccessMsg)
				}

				if userMessage.Method == "UPDATE" {
					if clientInfo.PowerLevel < 50 {
						log.Warning("User does not have a high enough power level!")
						permError := ErrorMessage{
							Type:    "error",
							Message: "You don't have a high enough power level.",
							Code:    "PWRLVL",
						}
						log.Debug("OUT", permError)
						conn.WriteJSON(permError)
						break
					}

					var clientToUpdate Client

					db.First(&clientToUpdate, "user_id = ?", userMessage.UserID)
					clientToUpdate.PowerLevel = userMessage.PowerLevel
					db.Save(&clientToUpdate)

					successMsg := InfoMessage{
						Type:      "serverMessage",
						MessageID: uuid.NewV4(),
						Message:   "Client has been mutated.",
					}
					conn.WriteJSON(successMsg)

					for _, sub := range channelSubs {
						if sub.UserID == clientToUpdate.UserID {
							// give client their new user info
							clientMsg := ClientInfo{
								Type:   "clientInfo",
								Client: clientToUpdate,
							}
							conn.WriteJSON(clientMsg)
						}
					}
				}
				// can only be used by yourself
				if userMessage.Method == "NICK" {
					oldUsername := clientInfo.Username

					if len(userMessage.Username) > 9 {
						nickError := ErrorMessage{
							Type:    "error",
							Message: "The max username length is 9 characters.",
						}
						log.Debug("OUT", nickError)
						conn.WriteJSON(nickError)
						break
					}

					db.Model(&clientInfo).Update("username", userMessage.Username)
					clientInfo.Username = userMessage.Username
					// broadcast the nick change message
					var userNickChgMsg ChatMessage

					db.Create(&userNickChgMsg)

					userNickChgMsg.Type = "chat"
					userNickChgMsg.ChannelID = userMessage.ChannelID
					userNickChgMsg.MessageID = uuid.NewV4()
					userNickChgMsg.Method = "CREATE"
					userNickChgMsg.Type = "chat"
					userNickChgMsg.Username = "Server Message"
					userNickChgMsg.Message = oldUsername + " changed their nickname to " + userMessage.Username

					db.Save(&userNickChgMsg)

					clientInfo.Username = userMessage.Username

					for _, sub := range channelSubs {
						if sub.ChannelID == userMessage.ChannelID {
							sub.Connection.WriteJSON(userNickChgMsg)
						}
					}
					// give client their user info
					clientMsg := ClientInfo{
						Type:   "clientInfo",
						Client: clientInfo,
					}
					conn.WriteJSON(clientMsg)
				}
			case "ping":
				var pongMsg PongMessage
				json.Unmarshal(msg, &pongMsg)

				pongMsg.Type = "pong"
				log.Debug("OUT", pongMsg)
				conn.WriteJSON(pongMsg)
			case "userInfo":
				if !authed {
					log.Warning("Not authorized!")
					conn.Close()
					break
				}
				var userInfoMsg UserInfoMsg
				json.Unmarshal(msg, &userInfoMsg)

				userList := []Client{}
				db.Where("username = ?", userInfoMsg.Username).Find(&userList)

				matchList := []Client{}

				for _, usr := range userList {
					tag := usr.UserID.String()[9:13]
					if tag == userInfoMsg.UserTag {
						matchList = append(matchList, usr)
					}
				}

				userInfoRes := UserInfoRes{
					MessageID: userInfoMsg.MessageID,
					Type:      "userInfoRes",
					Method:    userInfoMsg.Method,
					MatchList: matchList,
				}
				conn.WriteJSON(userInfoRes)
			case "channelPerm":
				if !authed {
					log.Warning("Not authorized!")
					conn.Close()
					break
				}
				if clientInfo.PowerLevel < 50 {
					log.Warning("User not authorized to change channel permissions!")
					break
				}

				var permMsg ChannelPermMsg
				json.Unmarshal(msg, &permMsg)

				if permMsg.Method == "CREATE" {

					// if it's the empty uuid
					if permMsg.Permission.UserID.String() == emptyUserID {
						log.Warning("CREATE channelPerm sent without UUID, UUID is a required parameter.")
						break
					}

					existingPermissions := []ChannelPermission{}
					duplicate := false

					db.Where("user_id = ?", permMsg.Permission.UserID).Find(&existingPermissions)
					for _, prm := range existingPermissions {
						if prm.ChannelID == permMsg.Permission.ChannelID {
							var challengeError ErrorMessage
							challengeError.Type = "error"
							challengeError.Message = "That user already has permission to that channel."
							log.Debug("OUT", challengeError)
							conn.WriteJSON(challengeError)
							log.Warning("Duplicate permission requested.")
							duplicate = true
							break
						}
					}

					if duplicate {
						break
					}

					if permMsg.Permission.PowerLevel > clientInfo.PowerLevel {
						log.Warning("User does not have high enough power level to create permission.")
						var challengeError ErrorMessage
						challengeError.Type = "error"
						challengeError.Message = "You can't create a permission with a power level higher than yourself."
						log.Debug("OUT", challengeError)
						conn.WriteJSON(challengeError)
						break
					}

					db.Create(&permMsg.Permission)
					successMsg := SuccessMessage{
						Type:      "channelPermRes",
						MessageID: uuid.NewV4(),
						Status:    "SUCCESS",
					}
					log.Debug("OUT", successMsg)
					conn.WriteJSON(successMsg)

					for _, chanSub := range channelSubs {
						if chanSub.UserID == permMsg.Permission.UserID {
							grantMessage := InfoMessage{
								Type:      "serverMessage",
								MessageID: uuid.NewV4(),
								Message:   "You have been granted access to a new channel. Check /channel ls for details.",
							}
							chanSub.Connection.WriteJSON(grantMessage)
						}
					}
				}

				if permMsg.Method == "DELETE" {
					cPerms := []ChannelPermission{}
					db.Where("user_id = ?", permMsg.Permission.UserID).Find(&cPerms)

					found := false
					for _, perm := range cPerms {
						if perm.ChannelID == permMsg.Permission.ChannelID {
							found = true
							db.Delete(&perm)
							log.Debug("Deleted user permission.")
							successMes := InfoMessage{
								Type:      "serverMessage",
								MessageID: uuid.NewV4(),
								Message:   "You have revoked permission for user " + permMsg.Permission.UserID.String(),
							}
							conn.WriteJSON(successMes)
							break
						}
					}

					if !found {
						delErr := ErrorMessage{
							Type:    "error",
							Code:    "NOPERMEXISTS",
							Message: "No permissions exist for that channel.",
						}
						log.Debug("OUT", delErr)
						conn.WriteJSON(delErr)
					} else {
						for _, sub := range channelSubs {
							if sub.ChannelID == permMsg.Permission.ChannelID && sub.UserID == permMsg.Permission.UserID {
								delErr := ErrorMessage{
									Type:    "error",
									Code:    "NOPERMEXISTS",
									Message: "Your permissions to this channel have been revoked.",
								}
								log.Debug("OUT", delErr)
								sub.Connection.WriteJSON(delErr)
								sub.Connection.Close()
							}
						}
					}
				}
			case "chat":
				if !authed {
					log.Warning("Not authorized!")
					conn.Close()
					break
				}
				var chatMessage ChatMessage
				json.Unmarshal(msg, &chatMessage)

				db.Create(&chatMessage)

				chatMessage.UserID = clientInfo.UserID
				chatMessage.MessageID = uuid.NewV4()
				chatMessage.Username = clientInfo.Username

				db.Save(&chatMessage)

				found := false
				for _, sub := range channelSubs {
					if sub.ChannelID == chatMessage.ChannelID {
						sub.Connection.WriteJSON(chatMessage)
						found = true
					}
				}
				if found {
					log.Debug("BROADCAST", chatMessage)
				} else {
					log.Warning("Client is sending message to channel that is not active.")
				}

			case "channel":
				if !authed {
					log.Warning("Not authorized!")
					conn.Close()
					break
				}

				var channelMessage ChannelMessage
				json.Unmarshal(msg, &channelMessage)

				if channelMessage.Method == "LEAVE" {
					for true {
						if len(channelSubs) == 0 {
							break
						}
						scanCompleted := false
						fmt.Println(channelMessage)
						for i, sb := range channelSubs {
							if sb.ChannelID == channelMessage.ChannelID && sb.UserID == clientInfo.UserID && sb.Connection == conn {
								leaveMsgRes := ChannelMessage{
									Type:      "channelLeaveMsgRes",
									Method:    "LEAVE",
									ChannelID: channelMessage.ChannelID,
									MessageID: uuid.NewV4(),
								}
								sb.Connection.WriteJSON(leaveMsgRes)

								// remove this entry from slice
								channelSubs = append(channelSubs[:i], channelSubs[i+1:]...)
								break
							}

							if i == len(channelSubs)-1 {
								scanCompleted = true
							}
						}
						if scanCompleted {
							break
						}
					}
				}

				if channelMessage.Method == "CREATE" {

					if clientInfo.PowerLevel < 50 {
						log.Warning("User does not have create permissions.")
						var challengeError ErrorMessage
						challengeError.Type = "error"
						challengeError.Message = "You don't have a high enough power level."
						log.Debug("OUT", challengeError)
						conn.WriteJSON(challengeError)
						break
					}

					var newChannel Channel
					newChannel.ChannelID = uuid.NewV4()
					newChannel.Admin = clientInfo.UserID
					newChannel.Public = !channelMessage.Private
					newChannel.Name = channelMessage.Name

					if !newChannel.Public {
						var channelPerm ChannelPermission
						db.Create(&channelPerm)
						channelPerm.UserID = clientInfo.UserID
						channelPerm.ChannelID = newChannel.ChannelID
						channelPerm.PowerLevel = 100
						db.Save(&channelPerm)
					}

					db.Create(&newChannel)
					sendChannelList(conn, db, log, clientInfo)
				}

				if channelMessage.Method == "RETRIEVE" {
					sendChannelList(conn, db, log, clientInfo)
				}

				if channelMessage.Method == "DELETE" {
					if clientInfo.PowerLevel < 50 {
						log.Warning("User does not have delete permissions.")
						var challengeError ErrorMessage
						challengeError.Type = "error"
						challengeError.Message = "You don't have a high enough power level."
						log.Debug("OUT", challengeError)
						conn.WriteJSON(challengeError)
						break
					}
					var deletedChannel Channel
					db.First(&deletedChannel, "channel_id = ?", channelMessage.ChannelID)
					if deletedChannel.ID == 0 {
						log.Warning("Channel DELETE request for nonexistant channel.")
						break
					}
					db.Delete(&deletedChannel)
					for _, sub := range channelSubs {
						if sub.ChannelID == channelMessage.ChannelID {
							delMsg := InfoMessage{
								Type:      "serverMessage",
								MessageID: uuid.NewV4(),
								Message:   "The channel has been deleted.",
							}

							if sub.UserID != clientInfo.UserID {
								sub.Connection.WriteJSON(delMsg)
							}
							scanComplete := false
							for true {
								if len(channelSubs) == 0 {
									break
								}
								for i, sb := range channelSubs {
									if sb.ChannelID == channelMessage.ChannelID {
										channelSubs = append(channelSubs[:i], channelSubs[i+1:]...)
										break
									}

									if i == len(channelSubs)-1 {
										scanComplete = true
									}
								}
								if scanComplete {
									break
								}
							}

						}
					}
					successMsg := InfoMessage{
						Type:      "serverMessage",
						MessageID: uuid.NewV4(),
						Message:   "The channel has been deleted.",
					}
					conn.WriteJSON(successMsg)
				}

				if channelMessage.Method == "JOIN" {

					var requestedChannel Channel
					db.First(&requestedChannel, "channel_id = ?", channelMessage.ChannelID.String())

					if !requestedChannel.Public {
						hasPermission := false

						cPerms := []ChannelPermission{}
						db.Where("user_id = ?", clientInfo.UserID).Find(&cPerms)

						for _, perm := range cPerms {
							if perm.ChannelID == requestedChannel.ChannelID {
								hasPermission = true
							}
						}

						if !hasPermission {
							log.Warning("User is requesting access to channel he does not have permission to.")
							prmErr := ErrorMessage{
								Type:    "error",
								Code:    "NOACCESS",
								Message: "You don't have permission to that.",
							}
							log.Debug("OUT", prmErr)
							conn.WriteJSON(prmErr)
							break
						}
					}

					if requestedChannel.ID == 0 {
						log.Warning("Client attempted subscription to nonexistant channel id " + requestedChannel.ChannelID.String())
						break
					}

					duplicate := false
					for _, sub := range channelSubs {
						if sub.ChannelID == channelMessage.ChannelID && sub.UserID == clientInfo.UserID && sub.Connection == conn {
							log.Warning("Duplicate subscription from client, not adding.")
							duplicate = true
							break
						}
					}

					if duplicate {
						break
					}

					var newSub ChannelSub
					newSub.UserID = clientInfo.UserID
					newSub.ChannelID = requestedChannel.ChannelID
					newSub.Connection = conn

					channelSubs = append(channelSubs, &newSub)
					joinedChannelIDs = append(joinedChannelIDs, newSub.ChannelID)

					var chanRes ChannelResponse
					chanRes.ChannelID = requestedChannel.ChannelID
					chanRes.Method = channelMessage.Method
					chanRes.Name = requestedChannel.Name
					chanRes.Status = "SUCCESS"
					chanRes.Type = "channelJoinRes"

					log.Debug("OUT", chanRes)
					conn.WriteJSON(chanRes)
				}

			case "challengeRes":
				var challengeResponse ChallengeResponse
				json.Unmarshal(msg, &challengeResponse)

				var clientKeys KeyPair
				clientPubKey, _ := hex.DecodeString(challengeResponse.PubKey)
				clientKeys.Pub = clientPubKey

				for _, sub := range challengeSubscriptions {
					if sub.PubKey == challengeResponse.PubKey {
						challengeKey, _ := hex.DecodeString(sub.PubKey)
						challengeSig, _ := hex.DecodeString(challengeResponse.Response)
						if ed25519.Verify(challengeKey, []byte(sub.MessageID.String()), challengeSig) {
							log.Notice("User authorized successfully.")
							authed = true

							// give client the auth success message
							authResult := AuthResultMessage{
								MessageID: uuid.NewV4(),
								Status:    "SUCCESS",
								Type:      "authResult",
							}
							log.Debug("OUT", authResult)
							conn.WriteJSON(authResult)

							// give client their user info
							clientMsg := ClientInfo{
								Type:   "clientInfo",
								Client: clientInfo,
							}

							conn.WriteJSON(clientMsg)

							// send server welcome message
							welcomeMessage := WelcomeMessage{
								MessageID: uuid.NewV4(),
								Type:      "welcomeMessage",
								Message:   "Welcome to ExtraHash's server!\nHave fun and keep it clean! :D",
							}
							log.Debug("OUT", welcomeMessage)
							conn.WriteJSON(welcomeMessage)

							// send the channel list
							sendChannelList(conn, db, log, clientInfo)

							wsClients = append(wsClients, conn)
						}
					}
				}
			case "historyReq":
				if !authed {
					log.Warning("Not authorized!")
					conn.Close()
					break
				}
				var historyReq HistoryReqMessage
				json.Unmarshal(msg, &historyReq)

				log.Debug("IN", historyReq)

				var topMessage ChatMessage
				db.First(&topMessage, "message_id = ?", historyReq.TopMessage)

				// retrieve history and send to client
				messages := []ChatMessage{}
				db.Where("id > ?", topMessage.ID).Where("channel_id = ?", historyReq.ChannelID).Find(&messages)

				for _, msg := range messages {
					conn.WriteJSON(msg)
				}

				successMsg := SuccessMessage{
					Type:      "historyReqRes",
					MessageID: historyReq.MessageID,
					Status:    "SUCCESS",
				}
				log.Debug("OUT", successMsg)
				conn.WriteJSON(successMsg)

			case "challenge":
				// respond to challenge
				var challengeMessage ChallengeMessage
				json.Unmarshal(msg, &challengeMessage)

				var user Client
				db.First(&user, "pub_key = ?", challengeMessage.PubKey)

				if user.ID == 0 {
					var challengeError ErrorMessage
					challengeError.Type = "error"
					challengeError.Message = "You need to register first!"
					log.Debug("OUT", challengeError)
					conn.WriteJSON(challengeError)
					break
				}

				if user.Banned == true {
					banErr := ErrorMessage{
						Type:    "error",
						Code:    "BANNED",
						Message: "You have been banned.",
					}
					log.Debug("OUT", banErr)
					conn.WriteJSON(banErr)
					conn.Close()
				}

				clientInfo = user

				var challengeResponse ChallengeResponse
				challengeResponse.Type = "challengeRes"
				challengeResponse.MessageID = challengeMessage.MessageID
				challengeResponse.Response = hex.EncodeToString(ed25519.Sign(keys.Priv, []byte(challengeMessage.MessageID.String())))
				challengeResponse.PubKey = hex.EncodeToString(keys.Pub)
				log.Debug("OUT", challengeResponse)
				conn.WriteJSON(challengeResponse)

				// challenge the client
				var challengeToClient ChallengeMessage
				challengeToClient.MessageID = uuid.NewV4()
				challengeToClient.Type = "challenge"
				challengeToClient.PubKey = hex.EncodeToString(keys.Pub)

				var challengeSub ChallengeSub
				challengeSub.PubKey = challengeMessage.PubKey
				challengeSub.MessageID = challengeToClient.MessageID

				challengeSubscriptions = append(challengeSubscriptions, challengeSub)

				log.Debug("OUT", challengeToClient)
				conn.WriteJSON(challengeToClient)
			case "identity":
				var identityMessage IdentityMessage
				json.Unmarshal(msg, &identityMessage)

				if identityMessage.Method == "CREATE" {
					var identityResponse IdentityResponse
					identityResponse.Method = "CREATE"
					identityResponse.Type = "identityCreateRes"
					identityResponse.UUID = uuid.NewV4()
					identityResponse.MessageID = identityMessage.MessageID
					identityResponse.Status = "SUCCESS"

					db.Create(&Client{UserID: identityResponse.UUID, Username: "Anonymous", PowerLevel: 0, Banned: false})
					log.Debug("OUT", identityResponse)
					conn.WriteJSON(identityResponse)
				}

				if identityMessage.Method == "REGISTER" {
					var clientKeyPair KeyPair
					clientKeyPair.Pub, _ = hex.DecodeString(identityMessage.PubKey)
					sig, _ := hex.DecodeString(identityMessage.Signed)

					if ed25519.Verify(clientKeyPair.Pub, []byte(identityMessage.UUID.String()), sig) {
						var newClient Client
						db.First(&newClient, "user_id = ?", identityMessage.UUID.String())

						if newClient.ID == 0 {
							log.Warning("UUID does not exist in database.")
							continue
						}

						if newClient.PubKey != "" {
							log.Warning("User already registered.")
						} else {
							db.Model(&newClient).Update("PubKey", identityMessage.PubKey)
							var idResponse IdentityResponse
							idResponse.Type = "identityRegisterRes"
							idResponse.Method = "register"
							idResponse.MessageID = identityMessage.MessageID
							idResponse.Status = "SUCCESS"
							idResponse.UUID = identityMessage.UUID

							log.Debug("OUT", idResponse)
							conn.WriteJSON(idResponse)
						}
					} else {
						log.Warning("Signature not verified.")
					}
				}
			// catchall
			default:
				log.Warning("Unsupported " + message.Type + " message received.")
			}
		}
	})
}

// Run starts the http server.
func (a *App) Run(addr string) {
	err := http.ListenAndServe(addr, a.Router)

	if err != nil {
		log.Fatal(err)
	}

	a.Log.Info("API listening on " + addr)
}
