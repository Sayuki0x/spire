package main

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/websocket"
	"github.com/jinzhu/gorm"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/ed25519"
)

// ConnectedClient is a single client connected to the server.
type ConnectedClient struct {
	UserID     uuid.UUID       `json:"userID"`
	UserEntry  *Client         `json:"userEntry"`
	Connection *websocket.Conn `json:"-"`
}

// ChannelSub is a subscription to a channel by the client.
type ChannelSub struct {
	UserID     uuid.UUID       `json:"userID"`
	ChannelID  uuid.UUID       `json:"channelID"`
	Connection *websocket.Conn `json:"-"`
	UserEntry  *Client         `json:"userEntry"`
}

// ChallengeSub is a subscription by the server to a challenge transmission ID.
type ChallengeSub struct {
	PubKey         string    `json:"pubkey"`
	Challenge      uuid.UUID `json:"challenge"`
	TransmissionID uuid.UUID `json:"transmissionID"`
}

func killUnauthedConnection(authed *bool, conn *websocket.Conn) {
	timer := time.NewTimer(3 * time.Second)
	<-timer.C

	if !*authed {
		conn.Close()
	}
}

func getChannelList(clientInfo *Client, db *gorm.DB) []Channel {
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

	return orderedChannels
}

func sendChannelList(conn *websocket.Conn, db *gorm.DB, clientInfo *Client, transmissionID uuid.UUID) {
	channels := getChannelList(clientInfo, db)

	channelPush := ChannelListPush{
		Type:           "channelList",
		MessageID:      uuid.NewV4(),
		TransmissionID: transmissionID,
		Channels:       channels,
	}

	sendMessage(channelPush, conn)
}

type OnlineList struct {
	Type           string    `json:"type"`
	MessageID      uuid.UUID `json:"messageID"`
	TransmissionID uuid.UUID `json:"transmissionID"`
	ChannelID      uuid.UUID `json:"channelID"`
	Users          []*Client `json:"data"`
}

func getDbEntry(userID uuid.UUID, db *gorm.DB) *Client {
	dbEntry := Client{}

	db.First(&dbEntry, "user_id = ?", userID)

	if dbEntry.ID == 0 {
		log.Fatal("User ID " + userID.String() + " doens't exist!")
	}

	return &dbEntry
}

func reverse(messages []ChatMessage) []ChatMessage {
	for i := 0; i < len(messages)/2; i++ {
		j := len(messages) - i - 1
		messages[i], messages[j] = messages[j], messages[i]
	}
	return messages
}

func getOnlineList(channelID uuid.UUID, db *gorm.DB) []*Client {
	usersInChannel := []*Client{}

	for _, sub := range channelSubs {
		if sub.ChannelID == channelID {
			usersInChannel = append(usersInChannel, getDbEntry(sub.UserID, db))
		}
	}

	return usersInChannel
}

func hasChannelPermission(channelID uuid.UUID, clientInfo *Client, db *gorm.DB) bool {
	hasPermission := false

	var requestedChannel Channel
	db.First(&requestedChannel, "channel_id = ?", channelID.String())

	if channelID.String() == emptyUserID {
		return false
	}

	if !requestedChannel.Public {

		cPerms := []ChannelPermission{}
		db.Where("user_id = ?", clientInfo.UserID).Find(&cPerms)

		for _, perm := range cPerms {
			if perm.ChannelID == requestedChannel.ChannelID {
				hasPermission = true
			}
		}
	} else {
		hasPermission = true
	}

	return hasPermission
}

func sendPowerlevels(conn *websocket.Conn, transmissionID uuid.UUID, config Config) {
	msg := PowerLevelPush{
		Type:           "powerLevels",
		MessageID:      uuid.NewV4(),
		TransmissionID: transmissionID,
		PowerLevels:    config.PowerLevels,
	}

	sendMessage(msg, conn)
}

func sendOnlineList(channelID uuid.UUID, transmissionID uuid.UUID, db *gorm.DB) {
	usersInChannel := getOnlineList(channelID, db)
	for _, sub := range channelSubs {
		if sub.ChannelID == channelID {
			oList := OnlineList{
				Type:           "onlineList",
				ChannelID:      channelID,
				MessageID:      uuid.NewV4(),
				TransmissionID: transmissionID,
				Users:          usersInChannel,
			}

			sendMessage(oList, sub.Connection)
		}
	}
}

func containsUUID(id []uuid.UUID, query uuid.UUID) bool {
	for _, a := range id {
		if a == query {
			return true
		}
	}
	return false
}

func sendClientInfo(conn *websocket.Conn, transmissionID uuid.UUID, clientInfo *Client) {
	// give client their user info
	clientMsg := ClientPush{
		Type:      "clientInfo",
		Client:    clientInfo,
		MessageID: uuid.NewV4(),
	}
	sendMessage(clientMsg, conn)
}

func getActiveChannels(client *Client) []uuid.UUID {
	activeChannels := []uuid.UUID{}

	for _, sub := range channelSubs {
		if sub.UserID == client.UserID {
			activeChannels = append(activeChannels, sub.ChannelID)
		}
	}

	return activeChannels
}

func broadcast(db *gorm.DB, Chat ChatMessage, clientInfo *Client, sendingConnection *websocket.Conn, transmissionID uuid.UUID) {
	db.Create(&Chat)

	sendingClient := Client{}

	db.First(&sendingClient, "user_id = ?", clientInfo.UserID)

	if sendingClient.ID == 0 {
		sendError("NOEXIST", "Not sure what happened here. You don't exist!", sendingConnection, transmissionID, Chat)
		return
	}

	Chat.UserID = sendingClient.UserID
	Chat.MessageID = uuid.NewV4()
	Chat.TransmissionID = uuid.NewV4()
	Chat.Username = sendingClient.Username

	db.Save(&Chat)

	sendSuccess(sendingConnection, transmissionID, Chat)

	found := false
	for _, sub := range channelSubs {
		if sub.ChannelID == Chat.ChannelID {
			sub.Connection.WriteJSON(Chat)
			found = true
		}
	}
	if found {
		byteResponse, _ := json.Marshal(Chat)
		log.Debug("BROADCAST", string(byteResponse))
	} else {
		log.Warning("Client is sending message to channel that is not active.")
		db.Delete(&Chat)
	}
}

func getUsersInChannels(channelList []uuid.UUID) []*Client {
	effectedUsers := []*Client{}

	for _, sub := range channelSubs {
		effected := false
		if containsUUID(channelList, sub.ChannelID) {
			effected = true
		}
		if effected {
			effectedUsers = append(effectedUsers, sub.UserEntry)
		}
	}

	return effectedUsers
}

func getConnection(userID uuid.UUID) *websocket.Conn {
	for _, client := range globalClientList {
		if client.UserID == userID {
			return client.Connection
		}
	}
	return nil
}

// SocketHandler handles the websocket connection messages and responses.
func SocketHandler(keys KeyPair, db *gorm.DB, config Config) http.Handler {
	return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		log.Info(req.Method, req.URL, GetIP(req))

		var upgrader = websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
		}

		upgrader.CheckOrigin = func(req *http.Request) bool { return true }

		conn, err := upgrader.Upgrade(res, req, nil)

		if err != nil {
			log.Warning(err)
			res.Write([]byte("the client is not using the websocket protocol: 'upgrade' token not found in 'Connection' header"))
			return
		}

		log.Info("Incoming websocket connection.")

		challengeSubscriptions := []ChallengeSub{}
		joinedChannelIDs := []uuid.UUID{}

		authed := false
		go killUnauthedConnection(&authed, conn)

		var clientInfo *Client

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
				for _, id := range deletedIds {
					sendOnlineList(id, uuid.NewV4(), db)
				}

				log.Debug("Subscriptions removed for " + clientInfo.UserID.String())
				return
			}

			var message BaseReq
			json.Unmarshal(msg, &message)

			transmissionID := message.TransmissionID

			if transmissionID.String() == emptyUserID {
				log.Warning("User sent message of type " + message.Type + " without transmissionID.")
				sendError("NOTRNSID", "You are required to include a transmission ID.", conn, transmissionID, msg)
				continue
			}

			if message.Type == "" {
				log.Warning("Invalid message: " + string(msg))
				continue
			}

			log.Notice("IN", string(msg))

			switch message.Type {
			case "user":
				if !authed {
					sendError("NOAUTH", "You're not authorized yet!", conn, transmissionID, msg)
					log.Warning("Not authorized!")
					break
				}

				var userMessage UserReq
				json.Unmarshal(msg, &userMessage)

				if userMessage.Method == "RETRIEVE" {
					retrievedClient := Client{}

					db.First(&retrievedClient, "user_id = ?", userMessage.UserID)

					if retrievedClient.ID == 0 {
						sendError("NOEXIST", "That user doesn't exist.", conn, transmissionID, userMessage)
					} else {
						sendSuccess(conn, transmissionID, retrievedClient)
					}
					break
				}

				if userMessage.Method == "BAN" {
					if clientInfo.PowerLevel < config.PowerLevels.Ban {
						sendError("PWRLVL", "You don't have a high enough power level.", conn, transmissionID, userMessage)
						break
					}

					var bannedUser Client
					db.First(&bannedUser, "user_id = ?", userMessage.UserID)

					if bannedUser.ID == 0 {
						log.Warning("Requested ban to user that does not exist.")
						break
					}

					if bannedUser.PowerLevel > clientInfo.PowerLevel {
						log.Warning("Requested a ban for user with higher power level.")
						sendError("PWRLVL", "You can't ban someone with a higher power level than you.", conn, transmissionID, userMessage)
						break
					}

					bannedUser.Banned = true
					db.Save(&bannedUser)

					for _, sub := range channelSubs {
						if sub.UserID == userMessage.UserID {
							sendError("BANNED", "You have been banned.", sub.Connection, transmissionID, userMessage)
							sub.Connection.Close()
						}
					}
					log.Info("Banned user " + userMessage.UserID.String())
					sendSuccess(conn, transmissionID, bannedUser)
				}

				if userMessage.Method == "KICK" {
					if clientInfo.PowerLevel < config.PowerLevels.Kick {
						sendError("PWRLVL", "You don't have a high enough power level.", conn, transmissionID, userMessage)
						break
					}

					var userRequested Client

					db.First(&userRequested, "user_id = ?", userMessage.UserID)

					if userRequested.ID == 0 {
						log.Warning("Requested to kick user that doesn't exist.")
						sendError("NOEXIST", "That user ID doesn't exist.", conn, transmissionID, userMessage)
						break
					}

					if userRequested.PowerLevel > clientInfo.PowerLevel {
						log.Warning("Requested to kick user with higher power level.")
						sendError("PWRLVL", "You can't kick someone with a higher power level than you.", conn, transmissionID, userMessage)
						break
					}

					for _, sub := range globalClientList {
						if sub.UserID == userMessage.UserID {
							sendError("KICKED", "You have been kicked.", sub.Connection, transmissionID, userMessage)
							sub.Connection.Close()
						}
					}
					log.Info("Kicked user " + userMessage.UserID.String())
					sendSuccess(conn, transmissionID, userRequested)
				}

				if userMessage.Method == "UPDATE" {
					if clientInfo.PowerLevel != 100 {
						log.Warning("User does not have a high enough power level!")
						sendError("PWRLVL", "You don't have a high enough power level.", conn, transmissionID, userMessage)
						break
					}

					var clientToUpdate Client

					db.First(&clientToUpdate, "user_id = ?", userMessage.UserID)
					clientToUpdate.PowerLevel = userMessage.PowerLevel
					db.Save(&clientToUpdate)

					sendSuccess(conn, transmissionID, clientToUpdate)

					for _, sub := range globalClientList {
						if sub.UserID == clientToUpdate.UserID {
							// give client their new user info
							clientMsg := ClientPush{
								Type:           "clientInfo",
								MessageID:      uuid.NewV4(),
								TransmissionID: transmissionID,
								Client:         &clientToUpdate,
							}
							sub.UserEntry = &clientToUpdate
							sendMessage(clientMsg, conn)
						}
					}
				}
				// can only be used by yourself
				if userMessage.Method == "NICK" {
					if len(userMessage.Username) > config.MaxUsernameLength {
						sendError("MAXLENGTH", "The max username length is "+strconv.Itoa(config.MaxUsernameLength)+" characters.", conn, transmissionID, userMessage)
						break
					}

					db.Model(&clientInfo).Update("username", userMessage.Username)
					clientInfo.Username = userMessage.Username

					sendSuccess(conn, transmissionID, clientInfo)
					activeChannels := getActiveChannels(clientInfo)

					for _, client := range globalClientList {
						if client.UserID == clientInfo.UserID {
							client.UserEntry = clientInfo
							sendClientInfo(client.Connection, transmissionID, clientInfo)
						}
					}

					for _, id := range activeChannels {
						sendOnlineList(id, uuid.NewV4(), db)
					}

				}
			case "file":
				if !authed {
					sendError("NOAUTH", "You're not authorized yet!", conn, transmissionID, msg)
					log.Warning("Not authorized!")
					break
				}

				fileMsg := FileReq{}
				json.Unmarshal(msg, &fileMsg)

				if fileMsg.Method == "DELETE" {
					file := File{}
					db.Where("file_id = ?", fileMsg.FileID).Find(&file)
					if file.ID == 0 {
						sendError("NOEXIST", "The requested file doesn't exist.", conn, transmissionID, fileMsg)
					}

					if file.OwnerID != clientInfo.UserID && clientInfo.PowerLevel < config.PowerLevels.Files {
						sendError("NOPERM", "You don't have permission to delete that file.", conn, transmissionID, fileMsg)
					}
					db.Delete(&file)
					sendSuccess(conn, transmissionID, file)
					break
				}

				var requestedChannel Channel
				db.First(&requestedChannel, "channel_id = ?", fileMsg.ChannelID.String())

				if !hasChannelPermission(requestedChannel.ChannelID, clientInfo, db) {
					log.Warning("User is sending file to channel he has no access to.")
					sendError("NOACCESS", "You don't have permission to that channel.", conn, transmissionID, fileMsg)
					break
				}

				if fileMsg.Method == "CREATE" {
					file, err := hex.DecodeString(fileMsg.File)
					check(err)
					fileID := uuid.NewV4()
					newFile := File{FileID: fileID, OwnerID: clientInfo.UserID, FileName: fileMsg.Filename, ChannelID: fileMsg.ChannelID}
					db.Create(&newFile)
					saveUploadedFile(fileID.String(), file)
					sendSuccess(conn, transmissionID, newFile)
					break
				}

				if fileMsg.Method == "RETRIEVE" {
					files := []File{}
					db.Where("channel_id = ?", fileMsg.ChannelID).Find(&files)
					sendSuccess(conn, transmissionID, files)
					break
				}
			case "ping":
				var pongMsg APIPong
				json.Unmarshal(msg, &pongMsg)
				pongMsg.MessageID = uuid.NewV4()
				pongMsg.Type = "pong"
				sendMessage(pongMsg, conn)
			case "channelPerm":
				if !authed {
					sendError("NOAUTH", "You're not authorized yet!", conn, transmissionID, msg)
					log.Warning("Not authorized!")
					break
				}

				var permMsg PermReq
				json.Unmarshal(msg, &permMsg)

				if permMsg.Method == "RETRIEVE" {
					if clientInfo.PowerLevel < config.PowerLevels.Revoke {
						log.Warning("User not authorized to retrieve channel permissions!")
						sendError("PWRLVL", "You don't have a high enough power level.", conn, transmissionID, permMsg)
						break
					}
					cPerms := []ChannelPermission{}
					db.Where("channel_id = ?", permMsg.Permission.ChannelID).Find(&cPerms)

					sendSuccess(conn, transmissionID, cPerms)
					break
				}

				if permMsg.Method == "CREATE" {

					if clientInfo.PowerLevel < config.PowerLevels.Grant {
						log.Warning("User not authorized to grant channel permissions!")
						sendError("PWRLVL", "You don't have a high enough power level.", conn, transmissionID, permMsg)
						break
					}

					// if it'id the empty uuid
					if permMsg.Permission.UserID.String() == emptyUserID {
						sendError("BADREQ", "Request missing required userID parameter.", conn, transmissionID, permMsg)
						break
					}

					existingPermissions := []ChannelPermission{}
					duplicate := false

					db.Where("user_id = ?", permMsg.Permission.UserID).Find(&existingPermissions)
					for _, prm := range existingPermissions {
						if prm.ChannelID == permMsg.Permission.ChannelID {
							sendError("ALREADYEXISTS", "That user already has permission to that channel.", conn, transmissionID, permMsg)
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
						sendError("PWRLVL", "You can't create a permission with a power level higher than yourself.", conn, transmissionID, permMsg)
						break
					}

					db.Create(&permMsg.Permission)
					sendSuccess(conn, transmissionID, permMsg.Permission)

					for _, client := range globalClientList {
						if client.UserID == permMsg.Permission.UserID {
							sendChannelList(client.Connection, db, client.UserEntry, transmissionID)
						}
					}

					sendOnlineList(permMsg.Permission.ChannelID, transmissionID, db)
				}

				if permMsg.Method == "DELETE" {
					if clientInfo.PowerLevel < config.PowerLevels.Revoke {
						sendError("PWRLVL", "You don't have a high enough power level.", conn, transmissionID, permMsg)
						log.Warning("User not authorized to revoke channel permissions!")
						break
					}

					cPerms := []ChannelPermission{}
					db.Where("user_id = ?", permMsg.Permission.UserID).Find(&cPerms)

					found := false
					for _, perm := range cPerms {
						if perm.ChannelID == permMsg.Permission.ChannelID {
							found = true
							db.Delete(&perm)
							log.Debug("Deleted user permission.")
							sendSuccess(conn, transmissionID, perm)
							break
						}
					}

					if !found {
						sendError("NOPERM", "No permissions exist for that channel.", conn, transmissionID, permMsg)
						break
					} else {
						for _, sub := range channelSubs {
							if sub.ChannelID == permMsg.Permission.ChannelID && sub.UserID == permMsg.Permission.UserID {
								sendError("REVOKED", "Your permissions to this channel have been revoked.", sub.Connection, transmissionID, permMsg)
								sub.Connection.Close()
							}
						}
					}
					sendOnlineList(permMsg.Permission.ChannelID, transmissionID, db)
				}
			case "chat":
				if !authed {
					sendError("NOAUTH", "You're not authorized yet!", conn, transmissionID, msg)
					log.Warning("Not authorized!")
					break
				}

				var chat ChatMessage
				json.Unmarshal(msg, &chat)

				var requestedChannel Channel
				db.First(&requestedChannel, "channel_id = ?", chat.ChannelID.String())

				if !hasChannelPermission(requestedChannel.ChannelID, clientInfo, db) {
					log.Warning("User is sending file to channel he has no access to.")
					sendError("NOACCESS", "You don't have permission to that channel.", conn, transmissionID, chat)
					break
				}

				if clientInfo.PowerLevel < config.PowerLevels.Talk {
					log.Warning("User attempted to chat but doesn't have a high enough power level.")
					sendError("PWRLVL", "You don't have a high enough power level.", conn, transmissionID, chat)
					break
				}
				broadcast(db, chat, clientInfo, conn, transmissionID)
			case "channel":
				if !authed {
					sendError("NOAUTH", "You're not authorized yet!", conn, transmissionID, msg)
					log.Warning("Not authorized!")
					break
				}

				var channelMessage ChannelReq
				json.Unmarshal(msg, &channelMessage)

				if channelMessage.Method == "ACTIVE" {
					if !hasChannelPermission(channelMessage.ChannelID, clientInfo, db) {
						log.Warning("User is requesting online list to channel he has no access to.")
						sendError("NOACCESS", "You don't have permission to that channel.", conn, transmissionID, channelMessage)
						break
					}

					sendSuccess(conn, transmissionID, getOnlineList(channelMessage.ChannelID, db))
				}

				if channelMessage.Method == "LEAVE" {
					if channelMessage.ChannelID.String() == emptyUserID {
						sendError("BADREQ", "Malformed request or no channel ID included.", conn, transmissionID, channelMessage)
						break
					}

					for true {
						if len(channelSubs) == 0 {
							break
						}
						scanCompleted := false
						for i, sb := range channelSubs {
							if sb.ChannelID == channelMessage.ChannelID && sb.UserID == clientInfo.UserID && sb.Connection == conn {
								sendSuccess(sb.Connection, transmissionID, sb)
								// remove this entry from slice
								channelSubs = append(channelSubs[:i], channelSubs[i+1:]...)
								sendOnlineList(sb.ChannelID, uuid.NewV4(), db)
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
					if clientInfo.PowerLevel < config.PowerLevels.Create {
						log.Warning("User does not have channel create permissions.")
						sendError("PWRLVL", "You don't have a high enough power level.", conn, transmissionID, channelMessage)
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
					sendSuccess(conn, transmissionID, newChannel)

					for _, client := range globalClientList {
						sendChannelList(client.Connection, db, client.UserEntry, uuid.NewV4())
					}
					break
				}

				if channelMessage.Method == "RETRIEVE" {
					sendSuccess(conn, transmissionID, getChannelList(clientInfo, db))
					break
				}

				if channelMessage.Method == "DELETE" {
					if clientInfo.PowerLevel < config.PowerLevels.Delete {
						log.Warning("User does not have delete permissions.")
						sendError("PWRLVL", "You don't have a high enough power level.", conn, transmissionID, channelMessage)
						break
					}
					if channelMessage.ChannelID.String() == emptyUserID {
						sendError("BADREQ", "Malformed request or no channel ID included.", conn, transmissionID, channelMessage)
						break
					}
					var deletedChannel Channel
					db.First(&deletedChannel, "channel_id = ?", channelMessage.ChannelID)
					log.Notice(deletedChannel)
					if deletedChannel.ID == 0 {
						log.Warning("Channel DELETE request for nonexistant channel.")
						sendError("NOEXIST", "That channel doesn't exist.", conn, transmissionID, channelMessage)
						break
					}
					db.Delete(&deletedChannel)
					for _, sub := range channelSubs {
						if sub.ChannelID == channelMessage.ChannelID {
							if sub.UserID != clientInfo.UserID {
								sendError("DELETED", "This channel has been deleted.", sub.Connection, transmissionID, channelMessage)
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
					sendSuccess(conn, transmissionID, deletedChannel)
					for _, client := range globalClientList {
						sendChannelList(client.Connection, db, client.UserEntry, uuid.NewV4())
					}
					break
				}

				if channelMessage.Method == "JOIN" {
					if channelMessage.ChannelID.String() == emptyUserID {
						sendError("BADREQ", "Malformed request or no channel ID included.", conn, transmissionID, channelMessage)
						break
					}

					if !hasChannelPermission(channelMessage.ChannelID, clientInfo, db) {
						log.Warning("User is sending file to channel he has no access to.")
						sendError("NOACCESS", "You don't have permission to that channel.", conn, transmissionID, channelMessage)
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
					newSub.ChannelID = channelMessage.ChannelID
					newSub.Connection = conn
					newSub.UserEntry = clientInfo

					channelSubs = append(channelSubs, &newSub)
					joinedChannelIDs = append(joinedChannelIDs, newSub.ChannelID)

					sendSuccess(conn, transmissionID, newSub)
					sendOnlineList(newSub.ChannelID, uuid.NewV4(), db)
					break
				}

			case "response":
				var challengeResponse Response
				json.Unmarshal(msg, &challengeResponse)

				if challengeResponse.TransmissionID.String() == emptyUserID {
					sendError("VRSNERR", "You are using an unsupported client. Please upgrade.", conn, transmissionID, challengeResponse)
					conn.Close()
					break
				}

				var clientKeys KeyPair
				clientPubKey, _ := hex.DecodeString(challengeResponse.PubKey)
				clientKeys.Pub = clientPubKey

				for _, sub := range challengeSubscriptions {
					if sub.PubKey == challengeResponse.PubKey {
						challengeKey, _ := hex.DecodeString(sub.PubKey)
						challengeSig, _ := hex.DecodeString(challengeResponse.Response)
						if ed25519.Verify(challengeKey, []byte(sub.Challenge.String()), challengeSig) {
							log.Info("User authorized successfully.")
							authed = true

							sendSuccess(conn, transmissionID, clientInfo)
							sendPowerlevels(conn, transmissionID, config)

							sendClientInfo(conn, transmissionID, clientInfo)

							// send the channel list
							sendChannelList(conn, db, clientInfo, sub.TransmissionID)

							// add to global client list
							connectedClient := ConnectedClient{
								UserID:     clientInfo.UserID,
								UserEntry:  clientInfo,
								Connection: conn,
							}
							globalClientList = append(globalClientList, connectedClient)
						}
					}
				}
			case "historyReq":
				if !authed {
					sendError("NOAUTH", "You're not authorized yet!", conn, transmissionID, msg)
					log.Warning("Not authorized!")
					break
				}
				var historyReq HistoryReq
				json.Unmarshal(msg, &historyReq)
				chatMessages := []ChatMessage{}

				// TODO: add an offset
				db.Order("id DESC").Limit(100).Where("channel_id = ?", historyReq.ChannelID).Find(&chatMessages)
				sendSuccess(conn, transmissionID, reverse(chatMessages))
			case "challenge":
				var challengeMessage Challenge
				json.Unmarshal(msg, &challengeMessage)

				var user Client
				db.First(&user, "pub_key = ?", challengeMessage.PubKey)

				if challengeMessage.TransmissionID.String() == emptyUserID {
					sendError("VRSNERR", "You are using an unsupported client. Please upgrade.", conn, transmissionID, challengeMessage)
					conn.Close()
					break
				}

				if user.ID == 0 || user.UserID.String() == emptyUserID {
					sendError("NOEXIST", "You need to register first!", conn, transmissionID, challengeMessage)
					break
				}

				if user.Banned == true {
					sendError("BANNED", "You have been banned.", conn, transmissionID, challengeMessage)
					conn.Close()
				}

				clientInfo = &user

				var challengeResponse Response
				challengeResponse.Type = "response"
				challengeResponse.MessageID = uuid.NewV4()
				challengeResponse.TransmissionID = transmissionID
				challengeResponse.Response = hex.EncodeToString(ed25519.Sign(keys.Priv, []byte(challengeMessage.Challenge.String())))
				challengeResponse.PubKey = hex.EncodeToString(keys.Pub)
				sendMessage(challengeResponse, conn)

				// challenge the client
				var challengeToClient Challenge
				challengeToClient.MessageID = uuid.NewV4()
				challengeToClient.TransmissionID = uuid.NewV4()
				challengeToClient.Challenge = uuid.NewV4()
				challengeToClient.Type = "challenge"
				challengeToClient.PubKey = hex.EncodeToString(keys.Pub)

				var challengeSub ChallengeSub
				challengeSub.PubKey = clientInfo.PubKey
				challengeSub.TransmissionID = challengeToClient.TransmissionID
				challengeSub.Challenge = challengeToClient.Challenge
				challengeSubscriptions = append(challengeSubscriptions, challengeSub)

				sendMessage(challengeToClient, conn)
			case "identity":
				var identityMessage IdentityReq
				json.Unmarshal(msg, &identityMessage)

				if !config.PublicRegistration {
					sendError("NOPUBRES", "Sorry, public registration isn't enabled on this server.", conn, transmissionID, identityMessage)
					log.Warning("Someone attempted to register, but registration is disabled.")
					return
				}

				if identityMessage.Method == "CREATE" {
					// create the new uuid
					newClient := Client{UserID: uuid.NewV4(), Username: "Anonymous", PowerLevel: 0, Banned: false}
					db.Create(&newClient)
					// send it back
					sendSuccess(conn, transmissionID, newClient)
				}

				if identityMessage.Method == "REGISTER" {
					var clientKeyPair KeyPair
					clientKeyPair.Pub, _ = hex.DecodeString(identityMessage.PubKey)
					sig, _ := hex.DecodeString(identityMessage.Signed)

					var registeredClient Client

					db.First(&registeredClient, "pub_key = ?", hex.EncodeToString(clientKeyPair.Pub))
					if registeredClient.ID != 0 {
						sendSuccess(conn, transmissionID, registeredClient)
						break
					}

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
							log.Info("Registration verified successfully. Creating user.")
							db.Model(&newClient).Update("PubKey", identityMessage.PubKey)
							sendSuccess(conn, transmissionID, newClient)
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
