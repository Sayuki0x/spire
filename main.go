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
)

const version string = "v0.1.0"

// Message is a type for websocket messages that pass to and from server and client.
type Message struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

// EdKeys is a type that contains a public and private ed25519 key.
type EdKeys struct {
	Pub    ed25519.PublicKey
	Priv   ed25519.PrivateKey
	Signed []byte
}

// PubKeys is a type that contains only public keys, as hex encoded strings.
type PubKeys struct {
	Pub    string
	Signed string
}

// App is the main app.
type App struct {
	Router *mux.Router
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

func checkKeys() EdKeys {
	_, pubKeyErr := os.Stat("config/key.pub")
	_, privKeyErr := os.Stat("config/key.priv")
	if os.IsNotExist(pubKeyErr) && os.IsNotExist(privKeyErr) {
		createKeyFiles()
	}

	var keys EdKeys

	keys.Pub = readBytesFromFile("config/key.pub")
	keys.Priv = readBytesFromFile("config/key.priv")

	return keys
}

// Initialize does the initialization of App.
func (a *App) Initialize() {
	checkConfig()
	var keys = checkKeys()

	router := mux.NewRouter()
	router.Handle("/socket", SocketHandler(keys)).Methods("GET")
	a.Router = router
}

func generateKeys() EdKeys {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal("Something went wrong generating the keys.")
	}

	var keys EdKeys

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

func createMessage(Type string, Data interface{}) ([]byte, error) {
	var response Message

	response.Type = Type
	response.Data = Data

	byteResponse, err := json.Marshal(response)
	if err != nil {
		log.Fatal("Programmer error!")
	}

	fmt.Println(string(byteResponse))

	return byteResponse, err
}

// SocketHandler handles the websocket connection messages and responses.
func SocketHandler(keys EdKeys) http.Handler {
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

			fmt.Println(message)

			switch message.Type {
			case "auth":
				fmt.Println("Auth message received.")

				var pubKeys PubKeys

				pubKeys.Pub = hex.EncodeToString(keys.Pub)
				pubKeys.Signed = hex.EncodeToString(ed25519.Sign(keys.Priv, keys.Pub))

				response, err := createMessage(message.Type, pubKeys)
				if err != nil {
					log.Fatal("Programmer error!")
					continue
				}
				conn.WriteMessage(msgType, response)
			case "version":
				response, err := createMessage(message.Type, version)
				if err != nil {
					log.Fatal("Programmer error!")
					continue
				}
				conn.WriteMessage(msgType, response)
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
