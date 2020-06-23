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
	Signed   string
}

// Message is a type for websocket messages that pass to and from server and client.
type Message struct {
	Type   string `json:"type"`
	PubKey string `json:"pubKey"`
}

// RegisterMessage is a type for authorization websocket messages that pass to and from server and client.
type RegisterMessage struct {
	Type   string  `json:"type"`
	PubKey string  `json:"pubKey"`
	Data   PubKeys `json:"data"`
}

// VersionMessage is a type for version websocket messages that pass to and from server and client.
type VersionMessage struct {
	Type   string      `json:"type"`
	PubKey string      `json:"pubKey"`
	Data   VersionData `json:"data"`
}

type ErrorMessage struct {
	Type   string `json:"type"`
	PubKey string `json:"pubKey"`
	Data   string `json:"data"`
}

type UserMessage struct {
	Type   string `json:"type"`
	PubKey string `json:"pubKey"`
	Data   Client `json:"data"`
}

// KeyPair is a type that contains a public and private ed25519 key.
type KeyPair struct {
	Pub    ed25519.PublicKey
	Priv   ed25519.PrivateKey
	Signed []byte
}

type VersionData struct {
	Version string
	Signed  string
}

// PubKeys is a type that contains only public keys, as hex encoded strings.
type PubKeys struct {
	Pub    string
	Signed string
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
	db, err := gorm.Open("sqlite3", "vex.sqlite3")
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

func createErrorMessage(Type string, pubKey string, Data string) ([]byte, error) {
	var response ErrorMessage

	response.Type = Type
	response.Data = Data
	response.PubKey = pubKey

	byteResponse, err := json.Marshal(response)
	if err != nil {
		log.Fatal("Programmer error!")
	}

	return byteResponse, err
}

func createUserMessage(Type string, pubKey string, userData Client) ([]byte, error) {
	var userDetails UserMessage
	userDetails.Type = "user"
	userDetails.PubKey = pubKey
	userDetails.Data = userData

	byteResponse, err := json.Marshal(userDetails)
	if err != nil {
		log.Fatal("Programmer error!")
	}

	return byteResponse, err
}

func createVersionMessage(Type string, pubKey string, Data VersionData) ([]byte, error) {
	var response VersionMessage

	response.Type = Type
	response.Data = Data
	response.PubKey = pubKey

	byteResponse, err := json.Marshal(response)
	if err != nil {
		log.Fatal("Programmer error!")
	}

	return byteResponse, err
}

func createRegisterMessage(Type string, pubKey string, Data PubKeys) ([]byte, error) {
	var response RegisterMessage

	response.Type = Type
	response.Data = Data
	response.PubKey = pubKey

	byteResponse, err := json.Marshal(response)
	if err != nil {
		log.Fatal("Programmer error!")
	}

	return byteResponse, err
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

		for {
			msgType, msg, err := conn.ReadMessage()
			if err != nil {
				log.Error(err)
				return
			}

			var message Message
			json.Unmarshal(msg, &message)

			if message.Type == "" {
				log.Warning("Invalid message, closing connection.")
				conn.Close()
				break
			}

			log.Debug("IN ", string(msg))

			switch message.Type {
			// mutates the user
			case "user":
				var userMessage UserMessage
				json.Unmarshal(msg, &userMessage)

				var clientKeyPair KeyPair
				clientKeyPair.Pub, _ = hex.DecodeString(userMessage.PubKey)
				clientKeyPair.Signed, _ = hex.DecodeString(userMessage.Data.Signed)

				if ed25519.Verify(clientKeyPair.Pub, clientKeyPair.Pub, clientKeyPair.Signed) {
					var currentUserEntry Client
					db.First(&currentUserEntry, "pub_key = ?", userMessage.PubKey)

					if currentUserEntry.ID == 0 {
						log.Warning("User doesn't seem to exist with pubkey " + userMessage.PubKey)
						break
					} else {
						currentUserEntry.Username = userMessage.Data.Username
						db.Save(&currentUserEntry)
					}
					log.Debug("User updated " + userMessage.Data.UUID.String())
				} else {
					log.Warning("Invalid signature.")
					conn.Close()
				}
			// exchanges identities
			case "register":
				// first we parse the client's auth json
				var registerMessage RegisterMessage
				json.Unmarshal(msg, &registerMessage)

				var clientKeyPair KeyPair
				clientKeyPair.Pub, _ = hex.DecodeString(registerMessage.Data.Pub)
				clientKeyPair.Signed, _ = hex.DecodeString(registerMessage.Data.Signed)

				// if signature verifies
				if ed25519.Verify(clientKeyPair.Pub, clientKeyPair.Pub, clientKeyPair.Signed) {
					log.Notice("Client validated as " + registerMessage.Data.Pub)
					// then we construct our own RegisterMessage in reply
					var pubKeys PubKeys
					pubKeys.Pub = hex.EncodeToString(keys.Pub)
					pubKeys.Signed = hex.EncodeToString(ed25519.Sign(keys.Priv, keys.Pub))
					response, err := createRegisterMessage(message.Type, hex.EncodeToString(keys.Pub), pubKeys)
					if err != nil {
						log.Fatal("Programmer error!")
						continue
					}

					var clientDbEntry Client
					db.First(&clientDbEntry, "pub_key = ?", registerMessage.Data.Pub)

					// save the pubkey in db if not present
					if clientDbEntry.ID == 0 {
						clientUuid := uuid.NewV4()
						db.Create(&Client{PubKey: registerMessage.Data.Pub, UUID: clientUuid, Username: "Anonymous"})
					}

					// finally we respond to the websocket request
					log.Debug("OUT", string(response))
					conn.WriteMessage(msgType, response)

					userMessage, userError := createUserMessage(message.Type, hex.EncodeToString(keys.Pub), clientDbEntry)
					if userError != nil {
						log.Fatal("Programmer error!")
						continue
					}
					conn.WriteMessage(msgType, userMessage)

				} else {
					log.Warning("Invalid signature.")
					conn.Close()
				}
			// exchanges versions
			case "version":
				// first we read the client's version
				var clientVersion VersionMessage
				json.Unmarshal(msg, &clientVersion)

				clientPublicKey, _ := hex.DecodeString(clientVersion.PubKey)
				signature, _ := hex.DecodeString(clientVersion.Data.Signed)

				if ed25519.Verify(clientPublicKey, []byte(clientVersion.Data.Version), signature) {
					// first we check if user exists in database
					var clientDbEntry Client
					db.First(&clientDbEntry, "pub_key = ?", clientVersion.PubKey)

					// if they're not present, they need to register first
					if clientDbEntry.ID == 0 {
						log.Warning("User is not registered.")
						response, err := createErrorMessage("error", hex.EncodeToString(keys.Pub), "You need to register first.")
						log.Debug("OUT", string(response))
						if err != nil {
							log.Fatal("Programmer error!")
							continue
						}
						conn.WriteMessage(msgType, response)
					} else {
						// next we construct our own VersionMessage in reply
						var versionData VersionData
						versionData.Version = version
						versionData.Signed = hex.EncodeToString(ed25519.Sign(keys.Priv, []byte(version)))

						response, err := createVersionMessage("version", hex.EncodeToString(keys.Pub), versionData)
						if err != nil {
							log.Fatal("Programmer error!")
							continue
						}

						// finally we respond to the websocket request
						log.Debug("OUT", string(response))
						conn.WriteMessage(msgType, response)
					}
				} else {
					log.Warning("Invalid signature.")
					conn.Close()
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
