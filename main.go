package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"golang.org/x/crypto/ed25519"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

const version string = "v0.1.0"

type Message struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

type KeyPair struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

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

	writeBytesToFile("config/key.pub", keys.pub)
	writeBytesToFile("config/key.priv", keys.priv)
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
	// todo: implement reading from file
	return generateKeys()
}

func (a *App) Initialize() {
	checkConfig()
	var keys = checkKeys()

	router := mux.NewRouter()
	router.Handle("/socket", SocketHandler(keys)).Methods("GET")
	a.Router = router
}

func generateKeys() KeyPair {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal("Something went wrong generating the keys.")
	}

	var keys KeyPair

	keys.pub = pub
	keys.priv = priv

	return keys
}

func writeBytesToFile(filename string, bytes []byte) bool {
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

func createMessage(Type string, Data interface{}) ([]byte, error) {
	var response Message
	response.Type = Type
	response.Data = Data

	byteResponse, err := json.Marshal(response)
	if err != nil {
		log.Fatal("Programmer error!")
	}

	return byteResponse, err
}

func SocketHandler(keys KeyPair) http.Handler {
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
				response, err := createMessage(message.Type, hex.EncodeToString(keys.pub))
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

func (a *App) Run(addr string) {
	http.ListenAndServe(addr, a.Router)
}
