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
	UserEntry  Client          `json:"userEntry"`
	Connection *websocket.Conn `json:"-"`
}

// ChannelSub is a subscription to a channel by the client.
type ChannelSub struct {
	UserID     uuid.UUID       `json:"userID"`
	ChannelID  uuid.UUID       `json:"channelID"`
	Connection *websocket.Conn `json:"-"`
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

func sendChannelList(conn *websocket.Conn, db *gorm.DB, clientInfo Client, transmissionID uuid.UUID) {
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

	channelPush := ChannelListPush{
		Type:           "channelList",
		MessageID:      uuid.NewV4(),
		TransmissionID: transmissionID,
		Channels:       orderedChannels,
	}
	sendMessage(channelPush, conn)
}

func broadcast(db *gorm.DB, Chat ChatMessage, clientInfo Client, transmissionID uuid.UUID, sendingConnection *websocket.Conn) {
	db.Create(&Chat)

	Chat.UserID = clientInfo.UserID
	Chat.MessageID = uuid.NewV4()
	Chat.TransmissionID = uuid.NewV4()
	Chat.Username = clientInfo.Username

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
					log.Warning("Not authorized!")
					conn.Close()
					break
				}

				var userMessage UserReq
				json.Unmarshal(msg, &userMessage)

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
								Client:         clientToUpdate,
							}
							sub.UserEntry = clientToUpdate
							sendMessage(clientMsg, conn)
						}
					}
				}
				// can only be used by yourself
				if userMessage.Method == "NICK" {
					oldUsername := clientInfo.Username

					if len(userMessage.Username) > config.MaxUsernameLength {
						sendError("MAXLENGTH", "The max username length is "+strconv.Itoa(config.MaxUsernameLength)+" characters.", conn, transmissionID, userMessage)
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
					userNickChgMsg.TransmissionID = transmissionID
					userNickChgMsg.Method = "CREATE"
					userNickChgMsg.Type = "chat"
					userNickChgMsg.Username = "Server Message"
					userNickChgMsg.Message = oldUsername + " changed their nickname to " + userMessage.Username

					db.Save(&userNickChgMsg)

					clientInfo.Username = userMessage.Username

					for _, sub := range channelSubs {
						if sub.ChannelID == userMessage.ChannelID {
							sendMessage(userNickChgMsg, sub.Connection)
						}
					}

					sendSuccess(conn, transmissionID, clientInfo)
				}
			case "ping":
				var pongMsg APIPong
				json.Unmarshal(msg, &pongMsg)
				pongMsg.MessageID = uuid.NewV4()
				pongMsg.Type = "pong"
				sendMessage(pongMsg, conn)
			case "channelPerm":
				if !authed {
					log.Warning("Not authorized!")
					conn.Close()
					break
				}

				var permMsg PermReq
				json.Unmarshal(msg, &permMsg)

				if permMsg.Method == "CREATE" {

					if clientInfo.PowerLevel < config.PowerLevels.Grant {
						log.Warning("User not authorized to grant channel permissions!")
						sendError("PWRLVL", "You don't have a high enough power level.", conn, transmissionID, permMsg)
						break
					}

					// if it's the empty uuid
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
				}
			case "chat":
				if !authed {
					log.Warning("Not authorized!")
					conn.Close()
					break
				}

				var chat ChatMessage
				json.Unmarshal(msg, &chat)

				if clientInfo.PowerLevel < config.PowerLevels.Talk {
					log.Warning("User attempted to chat but doesn't have a high enough power level.")
					sendError("PWRLVL", "You don't have a high enough power level.", conn, transmissionID, chat)
					break
				}
				broadcast(db, chat, clientInfo, transmissionID, conn)

			case "channel":
				if !authed {
					log.Warning("Not authorized!")
					conn.Close()
					break
				}

				var channelMessage ChannelReq
				json.Unmarshal(msg, &channelMessage)

				if channelMessage.Method == "LEAVE" {
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
					sendChannelList(conn, db, clientInfo, transmissionID)
				}

				if channelMessage.Method == "RETRIEVE" {
					sendChannelList(conn, db, clientInfo, transmissionID)
				}

				if channelMessage.Method == "DELETE" {
					if clientInfo.PowerLevel < config.PowerLevels.Delete {
						log.Warning("User does not have delete permissions.")
						sendError("PWRLVL", "You don't have a high enough power level.", conn, transmissionID, channelMessage)
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
							sendError("NOACCESS", "You don't have permission to that.", conn, transmissionID, channelMessage)
							break
						}
					}

					if requestedChannel.ID == 0 {
						log.Warning("Client attempted subscription to nonexistant channel id " + requestedChannel.ChannelID.String())
						sendError("NOEXIST", "That channel doesn't exist.", conn, transmissionID, channelMessage)
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

					sendSuccess(conn, transmissionID, newSub)
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

							// give client their user info
							clientMsg := ClientPush{
								Type:           "clientInfo",
								Client:         clientInfo,
								MessageID:      uuid.NewV4(),
								TransmissionID: sub.TransmissionID,
							}
							sendMessage(clientMsg, conn)

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
					log.Warning("Not authorized!")
					conn.Close()
					break
				}
				var historyReq HistoryReq
				json.Unmarshal(msg, &historyReq)

				log.Debug("IN", historyReq)

				var topMessage ChatMessage
				db.First(&topMessage, "message_id = ?", historyReq.TopMessage)

				// retrieve history and send to client
				messages := []ChatMessage{}
				db.Where("id > ?", topMessage.ID).Where("channel_id = ?", historyReq.ChannelID).Find(&messages)
				sendSuccess(conn, transmissionID, messages)
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

				clientInfo = user

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
