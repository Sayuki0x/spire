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
)

const version string = "v0.1.0"

type Client struct {
	gorm.Model
	PubKey   string
	Username string
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
}

func createKeyFiles() {
	_, pubKeyErr := os.Stat("config/key.pub")
	if os.IsNotExist(pubKeyErr) {
		os.Create("config/key.pub")
	}
	_, privKeyErr := os.Stat("config/key.priv")
	if os.IsNotExist(privKeyErr) {
		os.Create("config/key.priv")
	}

	keys := generateKeys()

	writeBytesToFile("config/key.pub", keys.Pub)
	writeBytesToFile("config/key.priv", keys.Priv)
}

func checkConfig() {
	_, configErr := os.Stat("config")
	if os.IsNotExist(configErr) {
		os.Mkdir("config", 0700)
	}
	_, pubKeyErr := os.Stat("config/key.pub")
	_, privKeyErr := os.Stat("config/key.priv")
	if os.IsNotExist(privKeyErr) && os.IsNotExist(pubKeyErr) {
		createKeyFiles()
	}
}

func checkKeys() KeyPair {
	_, pubKeyErr := os.Stat("config/key.pub")
	_, privKeyErr := os.Stat("config/key.priv")
	if os.IsNotExist(pubKeyErr) && os.IsNotExist(privKeyErr) {
		createKeyFiles()
	}

	var keys KeyPair

	keys.Pub = readBytesFromFile("config/key.pub")
	keys.Priv = readBytesFromFile("config/key.priv")

	return keys
}

// Initialize does the initialization of App.
func (a *App) Initialize() {
	checkConfig()
	var keys = checkKeys()

	// initialize database
	db, err := gorm.Open("sqlite3", "vex.db")
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&Client{})
	a.Db = db

	// initialize router
	router := mux.NewRouter()
	router.Handle("/socket", SocketHandler(keys, db)).Methods("GET")
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

func readBytesFromFile(filename string) []byte {
	// Open file for reading
	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}

	data, err := ioutil.ReadAll(file)
	if err != nil {
		log.Fatal(err)
	}

	return data
}

func writeBytesToFile(filename string, bytes []byte) bool {
	file, openErr := os.OpenFile(filename, os.O_RDWR, 0700)
	if openErr != nil {
		log.Fatal("Error opening file " + filename + " for writing.")
		log.Fatal(openErr)
		return false
	}
	file.Write(bytes)
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
func SocketHandler(keys KeyPair, db *gorm.DB) http.Handler {
	return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {

		var upgrader = websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
		}

		upgrader.CheckOrigin = func(req *http.Request) bool { return true }

		conn, _ := upgrader.Upgrade(res, req, nil)
		fmt.Println("Connection opened!")

		for {
			msgType, msg, err := conn.ReadMessage()
			if err != nil {
				fmt.Println(err)
				return
			}

			var message Message
			json.Unmarshal(msg, &message)

			if message.Type == "" {
				fmt.Println("Invalid message, closing connection.")
				conn.Close()
				break
			}

			switch message.Type {
			case "register":
				// first we parse the client's auth json
				var registerMessage RegisterMessage
				json.Unmarshal(msg, &registerMessage)

				var clientKeyPair KeyPair
				clientKeyPair.Pub, _ = hex.DecodeString(registerMessage.Data.Pub)
				clientKeyPair.Signed, _ = hex.DecodeString(registerMessage.Data.Signed)

				// if signature verifies
				if ed25519.Verify(clientKeyPair.Pub, clientKeyPair.Pub, clientKeyPair.Signed) {
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

					if clientDbEntry.ID == 0 {
						db.Create(&Client{PubKey: registerMessage.Data.Pub, Username: registerMessage.Data.Pub})
					}

					// finally we respond to the websocket request
					conn.WriteMessage(msgType, response)
				} else {
					print("Invalid signature.")
					conn.Close()
				}

			case "version":
				// first we read the client's version
				var clientVersion VersionMessage
				json.Unmarshal(msg, &clientVersion)

				clientPublicKey, _ := hex.DecodeString(clientVersion.PubKey)
				signature, _ := hex.DecodeString(clientVersion.Data.Signed)

				if ed25519.Verify(clientPublicKey, []byte(clientVersion.Data.Version), signature) {
					// first we check if user exists in database

					fmt.Println(clientVersion.PubKey)

					var clientDbEntry Client
					db.First(&clientDbEntry, "pub_key = ?", clientVersion.PubKey)

					fmt.Println(clientDbEntry)

					// if they're not present, they need to register first
					if clientDbEntry.ID == 0 {
						response, err := createErrorMessage("error", hex.EncodeToString(keys.Pub), "You need to register first.")
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
						conn.WriteMessage(msgType, response)
					}
				} else {
					fmt.Println("Invalid signature.")
					conn.Close()
				}

			default:
				fmt.Println("Unsupported " + message.Type + " message received.")
			}
		}
	})
}

// Run starts the http server.
func (a *App) Run(addr string) {
	http.ListenAndServe(addr, a.Router)
}
