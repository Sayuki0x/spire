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

	"golang.org/x/crypto/ed25519"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"github.com/op/go-logging"
	uuid "github.com/satori/go.uuid"
)

const version string = "v0.1.0"

type Client struct {
	gorm.Model
	PubKey   string
	Username string
	UUID     uuid.UUID
}

// Message is a type for websocket messages that pass to and from server and client.
type Message struct {
	Type string `json:"type"`
}

type ChallengeSub struct {
	PubKey    string
	MessageID uuid.UUID
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
	Message string `json:"message"`
	Error   error  `json:"error"`
}

// KeyPair is a type that contains a public and private ed25519 key.
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
	log.Info("All Rights Reserved © 2020 ExtraHash")
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

	log.Info("Server public key " + hex.EncodeToString(keys.Pub))

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

		subscriptions := []ChallengeSub{}
		authed := false

		for {
			msgType, msg, err := conn.ReadMessage()

			if !authed {
				// fmt.Println("User not yet authed.")
			}

			if err != nil {
				log.Error(err)
				return
			}

			var message Message
			json.Unmarshal(msg, &message)

			if message.Type == "" {
				log.Warning("Invalid message: " + string(msg))
				continue
			}

			log.Debug("IN ", string(msg))

			switch message.Type {
			case "challengeRes":
				var challengeResponse ChallengeResponse
				json.Unmarshal(msg, &challengeResponse)

				var clientKeys KeyPair
				clientPubKey, _ := hex.DecodeString(challengeResponse.PubKey)
				clientKeys.Pub = clientPubKey

				for _, sub := range subscriptions {
					if sub.PubKey == challengeResponse.PubKey {
						challengeKey, _ := hex.DecodeString(sub.PubKey)
						challengeSig, _ := hex.DecodeString(challengeResponse.Response)
						if ed25519.Verify(challengeKey, []byte(sub.MessageID.String()), challengeSig) {
							log.Notice("User authorized successfully.")
							authed = true
						}
					}
				}
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

					byteChallengeError, _ := json.Marshal(challengeError)
					log.Debug("OUT", string(byteChallengeError))
					conn.WriteMessage(msgType, byteChallengeError)
					break
				}

				var challengeResponse ChallengeResponse
				challengeResponse.Type = "challengeRes"
				challengeResponse.MessageID = challengeMessage.MessageID
				challengeResponse.Response = hex.EncodeToString(ed25519.Sign(keys.Priv, []byte(challengeMessage.MessageID.String())))
				challengeResponse.PubKey = hex.EncodeToString(keys.Pub)

				byteResponse, _ := json.Marshal(challengeResponse)
				log.Debug("OUT", string(byteResponse))
				conn.WriteMessage(msgType, byteResponse)

				// challenge the client
				var challengeToClient ChallengeMessage
				challengeToClient.MessageID = uuid.NewV4()
				challengeToClient.Type = "challenge"
				challengeToClient.PubKey = hex.EncodeToString(keys.Pub)
				byteChallenge, _ := json.Marshal(challengeToClient)

				var challengeSub ChallengeSub
				challengeSub.PubKey = challengeMessage.PubKey
				challengeSub.MessageID = challengeToClient.MessageID

				subscriptions = append(subscriptions, challengeSub)
				log.Debug("OUT", string(byteChallenge))
				conn.WriteMessage(msgType, byteChallenge)
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
					byteResponse, err := json.Marshal(identityResponse)
					if err != nil {
						log.Fatal(err)
					}
					db.Create(&Client{UUID: identityResponse.UUID, Username: "Anonymous"})
					log.Debug("OUT", string(byteResponse))
					conn.WriteMessage(msgType, byteResponse)
				}

				if identityMessage.Method == "REGISTER" {
					var clientKeyPair KeyPair
					clientKeyPair.Pub, _ = hex.DecodeString(identityMessage.PubKey)
					// signedUUID, _ := hex.DecodeString(identityMessage.Signed)

					if /* ed25519.Verify(clientKeyPair.Pub, identityMessage.UUID.Bytes(), signedUUID) */ true {

						var newClient Client
						db.First(&newClient, "uuid = ?", identityMessage.UUID.String())

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

							byteResponse, _ := json.Marshal(idResponse)

							log.Debug("OUT", string(byteResponse))
							conn.WriteMessage(msgType, byteResponse)
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
	http.ListenAndServe(addr, a.Router)
	a.Log.Info("API listening on " + addr)
}
