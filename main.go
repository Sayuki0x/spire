package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"time"

	"golang.org/x/crypto/ed25519"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/mysql"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"github.com/op/go-logging"
	uuid "github.com/satori/go.uuid"
)

var wsClients = []*websocket.Conn{}
var channelSubs = []*ChannelSub{}

const version string = "1.2.0"
const emptyUserID = "00000000-0000-0000-0000-000000000000"

var defaultConfig = Config{
	WelcomeMessage:     "Welcome to the server!",
	DbType:             "sqlite3",
	DbConnectionStr:    "vex-server.db",
	PublicRegistration: true,
	Port:               8000,
	PowerLevels: RequiredPower{
		Kick:   25,
		Ban:    50,
		Op:     100,
		Grant:  50,
		Revoke: 50,
		Talk:   0,
		Create: 50,
		Delete: 50,
	},
}

// Dump of all data for import by another server
type Dump struct {
	Clients            []Client            `json:"clients"`
	Channels           []Channel           `json:"channels"`
	ChannelPermissions []ChannelPermission `json:"channelPermissions"`
	ChatMessages       []ChatMessage       `json:"chatMessage"`
}

// Model that hides unnecessary fields in json
type Model struct {
	ID        uint       `json:"index" gorm:"primary_key"`
	CreatedAt time.Time  `json:"-"`
	UpdatedAt time.Time  `json:"-"`
	DeletedAt *time.Time `json:"-" sql:"index"`
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

// ClientInfo is a message to the client with their login info
type ClientInfo struct {
	Type           string    `json:"type"`
	MessageID      uuid.UUID `json:"messageID"`
	TransmissionID uuid.UUID `json:"transmissionID"`
	Client         Client    `json:"client"`
}

// UserInfoMsg is a message from the client with a requested user's info
type UserInfoMsg struct {
	MessageID      uuid.UUID `json:"messageID"`
	Type           string    `json:"type"`
	Method         string    `json:"method"`
	TransmissionID uuid.UUID `json:"transmissionID"`
	Username       string    `json:"username"`
	UserTag        string    `json:"userTag"`
}

// UserInfoRes is a message from the client requesting a user's info.
type UserInfoRes struct {
	MessageID      uuid.UUID `json:"messageID"`
	Type           string    `json:"type"`
	Method         string    `json:"method"`
	MatchList      []Client  `json:"matchList"`
	TransmissionID uuid.UUID `json:"transmissionID"`
}

// ChannelPermMsg is a message from the client to perform operations on channels.
type ChannelPermMsg struct {
	MessageID      uuid.UUID `json:"messageID"`
	TransmissionID uuid.UUID `json:"transmissionID"`
	Type           string    `json:"type"`
	Method         string    `json:"method"`
	Permission     ChannelPermission
}

// WelcomeMessage is the message the server sends on login.
type WelcomeMessage struct {
	MessageID      uuid.UUID `json:"messageID"`
	TransmissionID uuid.UUID `json:"transmissionID"`
	Type           string    `json:"type"`
	Message        string    `json:"message"`
}

// PongMessage is a response to a ping.
type PongMessage struct {
	MessageID      uuid.UUID `json:"messageID"`
	TransmissionID uuid.UUID `json:"transmissionID"`
	Type           string    `json:"type"`
}

// HistoryReqMessage is a history request message.
type HistoryReqMessage struct {
	Type           string    `json:"type"`
	ChannelID      uuid.UUID `json:"channelID"`
	TransmissionID uuid.UUID `json:"transmissionID"`
	Method         string    `json:"method"`
	TopMessage     uuid.UUID `json:"topMessage"`
}

// ChatMessage is a type for emitted chat messages.
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

// ChannelMessage is a message from the client to perform operations on a channel.
type ChannelMessage struct {
	Type           string    `json:"type"`
	Method         string    `json:"method"`
	ChannelID      uuid.UUID `json:"channelID"`
	MessageID      uuid.UUID `json:"messageID"`
	TransmissionID uuid.UUID `json:"transmissionID"`
	Private        bool      `json:"privateChannel"`
	Name           string    `json:"name"`
}

// ChannelResponse is a response to a ChannelMessage.
type ChannelResponse struct {
	Type           string    `json:"type"`
	Method         string    `json:"method"`
	Status         string    `json:"status"`
	ChannelID      uuid.UUID `json:"channelID"`
	MessageID      uuid.UUID `json:"messageID"`
	TransmissionID uuid.UUID `json:"transmissionID"`
	Name           string    `json:"name"`
}

// AuthResultMessage is the message that is sent to the client after successful login.
type AuthResultMessage struct {
	Type           string    `json:"type"`
	Status         string    `json:"status"`
	MessageID      uuid.UUID `json:"messageID"`
	TransmissionID uuid.UUID `json:"transmissionID"`
}

// ChannelList is a message with a list of the user's permissioned channels.
type ChannelList struct {
	MessageID      uuid.UUID `json:"messageID"`
	TransmissionID uuid.UUID `json:"transmissionID"`
	Type           string    `json:"type"`
	Method         string    `json:"method"`
	Status         string    `json:"status"`
	Channels       []Channel `json:"channels"`
}

// UserMessage is a message to perform operations on users.
type UserMessage struct {
	MessageID      uuid.UUID `json:"messageID"`
	TransmissionID uuid.UUID `json:"transmissionID"`
	Type           string    `json:"type"`
	Method         string    `json:"method"`
	Username       string    `json:"username"`
	ChannelID      uuid.UUID `json:"channelID"`
	PowerLevel     int       `json:"powerLevel"`
	UserID         uuid.UUID `json:"userID"`
}

// Message is a type for websocket messages that pass to and from server and client.
type Message struct {
	Type           string    `json:"type"`
	TransmissionID uuid.UUID `json:"transmissionID"`
}

// SuccessMessage is a general success message, to be displayed by the client.
type SuccessMessage struct {
	Type           string    `json:"type"`
	TransmissionID uuid.UUID `json:"transmissionID"`
	MessageID      uuid.UUID `json:"messageID"`
	Message        string    `json:"message"`
	Status         string    `json:"status"`
}

// ChannelSub is a subscription to a channel.
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

// ChallengeMessage is what initiates a challenge.
type ChallengeMessage struct {
	Type           string    `json:"type"`
	MessageID      uuid.UUID `json:"messageID"`
	TransmissionID uuid.UUID `json:"transmissionID"`
	Challenge      uuid.UUID `json:"challenge"`
	PubKey         string    `json:"pubkey"`
}

// ChallengeResponse is the response to a challenge.
type ChallengeResponse struct {
	Type           string    `json:"type"`
	MessageID      uuid.UUID `json:"messageID"`
	Response       string    `json:"response"`
	PubKey         string    `json:"pubkey"`
	TransmissionID uuid.UUID `json:"transmissionID"`
}

// IdentityMessage is a message for performing operations on identities.
type IdentityMessage struct {
	Type           string    `json:"type"`
	Method         string    `json:"method"`
	PubKey         string    `json:"pubkey"`
	UUID           uuid.UUID `json:"uuid"`
	Signed         string    `json:"signed"`
	MessageID      uuid.UUID `json:"messageID"`
	TransmissionID uuid.UUID `json:"transmissionID"`
}

// IdentityResponse is a response to an IdentityMessage.
type IdentityResponse struct {
	Method         string    `json:"method"`
	Type           string    `json:"type"`
	MessageID      uuid.UUID `json:"messageID"`
	TransmissionID uuid.UUID `json:"transmissionID"`
	UUID           uuid.UUID `json:"uuid"`
	Status         string    `json:"status"`
}

// ErrorMessage is a general error message to be displayed by the client.
type ErrorMessage struct {
	TransmissionID uuid.UUID `json:"transmissionID"`
	MessageID      uuid.UUID `json:"messageID"`
	Type           string    `json:"type"`
	Code           string    `json:"code"`
	Message        string    `json:"message"`
	Error          error     `json:"error"`
}

// RequiredPower is the required power level for moderation operations. It is in the json config.
type RequiredPower struct {
	Kick   int `json:"kick"`
	Ban    int `json:"ban"`
	Op     int `json:"op"`
	Grant  int `json:"grant"`
	Revoke int `json:"revoke"`
	Talk   int `json:"talk"`
	Create int `json:"create"`
	Delete int `json:"delete"`
}

// Config is the user supplied json config
type Config struct {
	WelcomeMessage     string        `json:"welcomeMessage"`
	DbType             string        `json:"dbType"`
	DbConnectionStr    string        `json:"dbConnectionStr"`
	PublicRegistration bool          `json:"publicRegistration"`
	Port               int           `json:"port"`
	PowerLevels        RequiredPower `json:"powerLevels"`
}

// StatusRes is the status http api endpoing response.
type StatusRes struct {
	Version   string `json:"version"`
	Status    string `json:"status"`
	MessageID string `json:"messageID"`
	PublicKey string `json:"publicKey"`
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
	Config Config
}

func sendMessage(msg interface{}, conn *websocket.Conn) {
	jsonMessage, _ := json.Marshal(msg)
	log.Debug("OUT", string(jsonMessage))

	conn.WriteJSON(msg)
}

func sendError(code string, message string, conn *websocket.Conn, transmissionID uuid.UUID) {
	err := ErrorMessage{
		Type:           "error",
		Message:        message,
		MessageID:      uuid.NewV4(),
		TransmissionID: transmissionID,
		Code:           code,
	}
	sendMessage(err, conn)
}

func sendSuccess(Message string, conn *websocket.Conn, transmissionID uuid.UUID) {
	success := SuccessMessage{
		Type:           "serverMessage",
		MessageID:      uuid.NewV4(),
		TransmissionID: transmissionID,
		Message:        Message,
	}
	sendMessage(success, conn)
}

func printASCII() {
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

func broadcast(db *gorm.DB, chatMessage ChatMessage, clientInfo Client, transmissionID uuid.UUID) {
	db.Create(&chatMessage)

	chatMessage.UserID = clientInfo.UserID
	chatMessage.MessageID = uuid.NewV4()
	chatMessage.TransmissionID = transmissionID
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
		byteResponse, _ := json.Marshal(chatMessage)
		log.Debug("BROADCAST", string(byteResponse))
	} else {
		log.Warning("Client is sending message to channel that is not active.")
		db.Delete(&chatMessage)
	}
}

func createKeyFiles(keyFolder string) {
	log.Debug("Creating keyfiles.")

	if !fileExists(keyFolder + "/key.pub") {
		os.Create(keyFolder + "/key.pub")
	}
	if !fileExists(keyFolder + "/key.priv") {
		os.Create(keyFolder + "/key.priv")
	}

	keys := generateKeys()

	writeBytesToFile(keyFolder+"/key.pub", keys.Pub)
	writeBytesToFile(keyFolder+"/key.priv", keys.Priv)
}

func checkKeys(cliArgs CliArgs) KeyPair {
	keyFolder := cliArgs.keyFolder

	if keyFolder == "" {
		keyFolder = "keys"
	}

	if !fileExists(keyFolder) {
		log.Debug("Creating key folder.")
		os.Mkdir(keyFolder, 0700)
	}

	if !fileExists(keyFolder + "/key.priv") {
		createKeyFiles(keyFolder)
	}

	var keys KeyPair

	keys.Pub = readBytesFromFile(keyFolder + "/key.pub")
	keys.Priv = readBytesFromFile(keyFolder + "/key.priv")

	log.Info("Server Public key " + hex.EncodeToString(keys.Pub))

	return keys
}

var log *logging.Logger = logging.MustGetLogger("vex")

type CliArgs struct {
	dump               bool
	dumpFile           string
	slurp              bool
	slurpFile          string
	register           bool
	configPath         string
	keyFolder          string
	registerKey        string
	registerPowerLevel int
}

func getArgs() CliArgs {
	// get cli rawArgs
	rawArgs := os.Args[1:]

	cliArgs := CliArgs{}

	for i, arg := range rawArgs {
		if arg == "--help" {
			fmt.Println(`
--keys       /path/to/keyfolder         The path that your key folder is in. If it is not present, one will be generated.
--config     /path/to/config.json       The path that your config file is in. If it is not present, the default config will be written here.
--register   PubKey PowerLevel          Registers a user manually on the server. with a given public key and power level. Will print the user details.
--port       number                     Sets the port number to listen on.
--backup     /path/to/file.json         Dumps the database into JSON for import into another Vex Server.
--import     /path/to/file.json         Imports the JSON dump generated by another Vex Server.
			`)
			os.Exit(0)
		}
		if arg == "--dump" {
			cliArgs.dump = true
			if len(rawArgs) > i+1 {
				cliArgs.dumpFile = rawArgs[i+1]
			} else {
				log.Fatal("File path argument is required for dump. --dump /path/to/dump.json")
			}
		}

		if arg == "--import" {
			cliArgs.slurp = true

			if len(rawArgs) > i+1 {
				cliArgs.slurpFile = rawArgs[i+1]
			} else {
				log.Fatal("File argument is required for import. --import /path/to/dump.json")
			}
		}

		if arg == "--register" {
			if len(rawArgs) > i+2 {
				cliArgs.register = true
				cliArgs.registerKey = rawArgs[i+1]
				registerPowerLevel, err := strconv.Atoi(rawArgs[i+2])
				check(err)
				cliArgs.registerPowerLevel = registerPowerLevel
			} else {
				log.Fatal("Register argument requires a public key and powerlevel argument. --register pubkey 100")
			}
		}

		if arg == "--config" {
			if len(rawArgs) > i+1 {
				cliArgs.configPath = rawArgs[i+1]
			} else {
				log.Fatal("File argument is required for config. --config /path/to/config.json")
			}
		}

		if arg == "--keys" {
			if len(rawArgs) > i+1 {
				cliArgs.keyFolder = rawArgs[i+1]
			} else {
				log.Fatal("File argument is required for key folder. --config /path/to/keyfolder")
			}
		}
	}
	return cliArgs
}

// Initialize does the initialization of App.
func (a *App) Initialize() {
	cliArgs := getArgs()

	//initialize logger
	var format = logging.MustStringFormatter(
		`%{color}%{time:15:04:05.000} ▶ %{level:.4s}%{color:reset} %{message}`,
	)
	backend := logging.NewLogBackend(os.Stderr, "", 0)
	backendFormatter := logging.NewBackendFormatter(backend, format)
	logging.SetBackend(backendFormatter)

	printASCII()

	// initialize configuration files
	config := readConfig(cliArgs)
	keys := checkKeys(cliArgs)

	a.Config = config

	// initialize database, support sqlite and mysql
	db, err := gorm.Open(config.DbType, config.DbConnectionStr)
	check(err)
	db.AutoMigrate(&Client{})
	db.AutoMigrate(&Channel{})
	db.AutoMigrate(&ChatMessage{})
	db.AutoMigrate(&ChannelPermission{})
	a.Db = db

	if cliArgs.register {
		log.Notice("Registering user with pubkey " + cliArgs.registerKey)
		newID := uuid.NewV4()
		db.Create(&Client{UserID: newID, PubKey: cliArgs.registerKey, Username: "Anonymous", PowerLevel: cliArgs.registerPowerLevel, Banned: false})
		log.Notice("User created with power level " + strconv.Itoa(cliArgs.registerPowerLevel) + ", userID is " + newID.String())
		os.Exit(0)
	}

	if cliArgs.dump {
		log.Notice("Dumping backup data!")

		dump := Dump{}

		db.Find(&dump.Clients)
		db.Find(&dump.ChannelPermissions)
		db.Find(&dump.ChatMessages)
		db.Find(&dump.Channels)

		writeJSONFile(cliArgs.dumpFile, dump)
		log.Notice("Backup completed, saved to " + cliArgs.dumpFile)
		os.Exit(0)
	}

	if cliArgs.slurp {
		log.Notice("Importing dump data from " + cliArgs.slurpFile)
		jsonBytes := readJSONFile(cliArgs.slurpFile)

		var slurpData Dump
		json.Unmarshal(jsonBytes, &slurpData)

		for _, client := range slurpData.Clients {
			db.Create(&client)
		}

		for _, channel := range slurpData.Channels {
			db.Create(&channel)
		}

		for _, channelPerm := range slurpData.ChannelPermissions {
			db.Create(&channelPerm)
		}

		for _, chatMessage := range slurpData.ChatMessages {
			db.Create(&chatMessage)
		}

		log.Notice("Import complete!")
		os.Exit(0)
	}

	// initialize router
	router := mux.NewRouter()
	router.Handle("/socket", SocketHandler(keys, db, config)).Methods("GET")
	router.Handle("/", HomeHandler(keys.Pub)).Methods("GET")
	router.Handle("/status", StatusHandler(keys.Pub)).Methods("GET")

	a.Router = router
}

// SocketHandler handles the websocket connection messages and responses.
func StatusHandler(pubkey ed25519.PublicKey) http.Handler {
	return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		log.Info(req.Method, req.URL, GetIP(req))

		res.Header().Set("Content-Type", "application/json")
		res.WriteHeader(http.StatusOK)

		statusRes := StatusRes{
			Version:   version,
			Status:    "ONLINE",
			PublicKey: hex.EncodeToString(pubkey),
			MessageID: uuid.NewV4().String(),
		}

		byteRes, _ := json.Marshal(statusRes)

		res.Write(byteRes)
	})
}

// SocketHandler handles the websocket connection messages and responses.
func HomeHandler(pubkey ed25519.PublicKey) http.Handler {
	return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		log.Info(req.Method, req.URL, GetIP(req))

		res.WriteHeader(http.StatusOK)

		res.Write([]byte("<!DOCTYPE html>"))
		res.Write([]byte("<html>"))
		res.Write([]byte("<style> body { width: 50em; margin: 0 auto; font-family: monospace; } ul { list-style: none } </style>"))
		res.Write([]byte("<body>"))
		res.Write([]byte("<h1>Welcome to Vex!</h1>"))
		res.Write([]byte("<p>If you can see this, the vex server is running. Point your client to " + req.Host + " to chat.</p>"))
		res.Write([]byte("<h2>Server Information</h2>"))
		res.Write([]byte("<ul>"))
		res.Write([]byte("<li>Vex Version: " + version + "</li>"))
		res.Write([]byte("<li>Public Key: &nbsp;" + hex.EncodeToString(pubkey) + "</li>"))
		res.Write([]byte("<li>Hostname: &nbsp;&nbsp;&nbsp;" + req.Host + "</li>"))
		res.Write([]byte("<li>MessageID: &nbsp;&nbsp;" + uuid.NewV4().String() + "</li>"))
		res.Write([]byte("</ul>"))
		res.Write([]byte("<p>© LogicBite LLC 2019-2020. See included LICENSE for details.</p>"))
		res.Write([]byte("</body>"))
		res.Write([]byte("</html>"))
	})
}

func generateKeys() KeyPair {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	check(err)

	var keys KeyPair

	keys.Pub = pub
	keys.Priv = priv

	return keys
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

	var channelList ChannelList

	channelList.MessageID = uuid.NewV4()
	channelList.TransmissionID = transmissionID
	channelList.Type = "channelListResponse"
	channelList.Status = "SUCCESS"
	channelList.Method = "RETRIEVE"
	channelList.Channels = orderedChannels

	sendMessage(channelList, conn)
}

func readJSONFile(filename string) []byte {
	file, openErr := os.Open(filename)
	check(openErr)

	data, readErr := ioutil.ReadAll(file)
	check(readErr)

	return data
}

func check(e error) {
	if e != nil {
		log.Fatal(e)
	}
}

func writeJSONFile(filename string, data interface{}) {
	jsonBytes, parseErr := json.MarshalIndent(data, "", "   ")
	check(parseErr)

	writeErr := ioutil.WriteFile(filename, jsonBytes, 0700)
	check(writeErr)
}

func readBytesFromFile(filename string) []byte {
	// Open file for reading
	file, openErr := os.Open(filename)
	check(openErr)

	data, readErr := ioutil.ReadAll(file)
	check(readErr)

	bytes, _ := hex.DecodeString(string(data))

	return bytes
}

func writeBytesToFile(filename string, bytes []byte) bool {
	file, openErr := os.OpenFile(filename, os.O_RDWR, 0700)
	check(openErr)

	file.Write([]byte(hex.EncodeToString(bytes)))

	syncErr := file.Sync()
	check(syncErr)

	file.Close()
	return true
}

func fileExists(filename string) bool {
	_, configErr := os.Stat(filename)
	if os.IsNotExist(configErr) {
		return false
	}
	return true
}

func readConfig(cliArgs CliArgs) Config {
	configPath := cliArgs.configPath

	if configPath == "" {
		configPath = "config.json"
	}

	if !fileExists(configPath) {
		writeJSONFile(configPath, defaultConfig)
	}

	configBytes := readJSONFile(configPath)
	var config Config
	json.Unmarshal(configBytes, &config)

	return config
}

func main() {
	a := App{}
	a.Initialize()
	log.Info("Starting API on port " + strconv.Itoa(a.Config.Port))
	a.Run(":" + strconv.Itoa(a.Config.Port))
}

func killUnauthedConnection(authed *bool, conn *websocket.Conn) {
	timer := time.NewTimer(3 * time.Second)
	<-timer.C

	if !*authed {
		conn.Close()
	}
}

// GetIP from http request
func GetIP(r *http.Request) string {
	forwarded := r.Header.Get("X-FORWARDED-FOR")
	if forwarded != "" {
		return forwarded
	}
	return r.RemoteAddr
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

			var message Message
			json.Unmarshal(msg, &message)

			transmissionID := message.TransmissionID

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

				var userMessage UserMessage
				json.Unmarshal(msg, &userMessage)

				if userMessage.Method == "BAN" {
					if clientInfo.PowerLevel < config.PowerLevels.Ban {
						sendError("PWRLVL", "You don't have a high enough power level.", conn, transmissionID)
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
						sendError("PWRLVL", "You can't ban someone with a higher power level than you.", conn, transmissionID)
						break
					}

					bannedUser.Banned = true
					db.Save(&bannedUser)

					for _, sub := range channelSubs {
						if sub.UserID == userMessage.UserID {
							sendError("BANNED", "You have been banned.", sub.Connection, transmissionID)
							sub.Connection.Close()
						}
					}
					log.Info("Banned user " + userMessage.UserID.String())
					sendSuccess("You have banned user "+userMessage.UserID.String(), conn, transmissionID)
				}

				if userMessage.Method == "KICK" {
					if clientInfo.PowerLevel < config.PowerLevels.Kick {
						sendError("PWRLVL", "You don't have a high enough power level.", conn, transmissionID)
						break
					}

					var userRequested Client

					db.First(&userRequested, "user_id = ?", userMessage.MessageID)

					if userRequested.ID == 0 {
						log.Warning("Requested to kick user that doesn't exist.")
						sendError("NOEXIST", "That user ID doesn't exist.", conn, transmissionID)
						break
					}

					if userRequested.PowerLevel > clientInfo.PowerLevel {
						log.Warning("Requested to kick user with higher power level.")
						sendError("PWRLVL", "You can't kick someone with a higher power level than you.", conn, transmissionID)
						break
					}

					for _, sub := range channelSubs {
						if sub.UserID == userMessage.UserID {
							kickErr := ErrorMessage{
								Type:           "error",
								Code:           "KICKED",
								Message:        "You have been kicked.",
								MessageID:      uuid.NewV4(),
								TransmissionID: transmissionID,
							}
							sendMessage(kickErr, sub.Connection)
							sub.Connection.Close()
						}
					}
					log.Info("Kicked user " + userMessage.UserID.String())
					kickSuccessMsg := SuccessMessage{
						Type:           "serverMessage",
						MessageID:      uuid.NewV4(),
						TransmissionID: transmissionID,
						Message:        "You have kicked user " + userMessage.UserID.String(),
					}
					sendMessage(kickSuccessMsg, conn)
				}

				if userMessage.Method == "UPDATE" {
					if clientInfo.PowerLevel != 100 {
						log.Warning("User does not have a high enough power level!")
						permError := ErrorMessage{
							Type:           "error",
							Message:        "You don't have a high enough power level.",
							MessageID:      uuid.NewV4(),
							TransmissionID: transmissionID,
							Code:           "PWRLVL",
						}
						sendMessage(permError, conn)
						break
					}

					var clientToUpdate Client

					db.First(&clientToUpdate, "user_id = ?", userMessage.UserID)
					clientToUpdate.PowerLevel = userMessage.PowerLevel
					db.Save(&clientToUpdate)

					successMsg := SuccessMessage{
						Type:           "serverMessage",
						MessageID:      uuid.NewV4(),
						TransmissionID: transmissionID,
						Message:        "Client has been mutated.",
					}
					sendMessage(successMsg, conn)

					for _, sub := range channelSubs {
						if sub.UserID == clientToUpdate.UserID {
							// give client their new user info
							clientMsg := ClientInfo{
								Type:           "clientInfo",
								MessageID:      uuid.NewV4(),
								TransmissionID: transmissionID,
								Client:         clientToUpdate,
							}
							sendMessage(clientMsg, conn)
						}
					}
				}
				// can only be used by yourself
				if userMessage.Method == "NICK" {
					oldUsername := clientInfo.Username

					if len(userMessage.Username) > 9 {
						nickError := ErrorMessage{
							Type:           "error",
							Message:        "The max username length is 9 characters.",
							MessageID:      uuid.NewV4(),
							TransmissionID: transmissionID,
						}
						sendMessage(nickError, conn)
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
					// give client their user info
					clientMsg := ClientInfo{
						Type:           "clientInfo",
						Client:         clientInfo,
						MessageID:      uuid.NewV4(),
						TransmissionID: transmissionID,
					}
					sendMessage(clientMsg, conn)
				}
			case "ping":
				var pongMsg PongMessage
				json.Unmarshal(msg, &pongMsg)
				pongMsg.MessageID = uuid.NewV4()
				pongMsg.Type = "pong"
				sendMessage(pongMsg, conn)
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
					MessageID:      uuid.NewV4(),
					TransmissionID: userInfoMsg.TransmissionID,
					Type:           "userInfoRes",
					Method:         userInfoMsg.Method,
					MatchList:      matchList,
				}
				sendMessage(userInfoRes, conn)
			case "channelPerm":
				if !authed {
					log.Warning("Not authorized!")
					conn.Close()
					break
				}

				var permMsg ChannelPermMsg
				json.Unmarshal(msg, &permMsg)

				if permMsg.Method == "CREATE" {

					if clientInfo.PowerLevel < config.PowerLevels.Grant {
						log.Warning("User not authorized to grant channel permissions!")
						break
					}

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
							permAddErr := ErrorMessage{
								Type:           "error",
								Message:        "That user already has permission to that channel.",
								TransmissionID: transmissionID,
								MessageID:      uuid.NewV4(),
							}
							sendMessage(permAddErr, conn)
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
						sendError("PWRLVL", "You can't create a permission with a power level higher than yourself.", conn, transmissionID)
						break
					}

					db.Create(&permMsg.Permission)
					sendSuccess("Permission added successfully.", conn, transmissionID)

					for _, chanSub := range channelSubs {
						if chanSub.UserID == permMsg.Permission.UserID {
							sendSuccess("You have been granted access to a new channel. Check /channel ls for details.", chanSub.Connection, transmissionID)
						}
					}
				}

				if permMsg.Method == "DELETE" {
					if clientInfo.PowerLevel < config.PowerLevels.Revoke {
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
							sendSuccess("You have revoked permission for user "+permMsg.Permission.UserID.String(), conn, transmissionID)
							break
						}
					}

					if !found {
						sendError("NOPERM", "No permissions exist for that channel.", conn, transmissionID)
						break
					} else {
						for _, sub := range channelSubs {
							if sub.ChannelID == permMsg.Permission.ChannelID && sub.UserID == permMsg.Permission.UserID {
								sendError("REVOKED", "Your permissions to this channel have been revoked.", sub.Connection, transmissionID)
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
				if clientInfo.PowerLevel < config.PowerLevels.Talk {
					log.Warning("User attempted to chat but doesn't have a high enough power level.")
					sendError("PWRLVL", "You don't have a high enoug power level to chat.", conn, transmissionID)
					break
				}
				var chatMessage ChatMessage
				json.Unmarshal(msg, &chatMessage)

				broadcast(db, chatMessage, clientInfo, transmissionID)
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
									Type:           "channelLeaveMsgRes",
									Method:         "LEAVE",
									ChannelID:      channelMessage.ChannelID,
									MessageID:      uuid.NewV4(),
									TransmissionID: transmissionID,
								}
								sendMessage(leaveMsgRes, sb.Connection)

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
						sendError("PWRLVL", "You don't have a high enough power level.", conn, transmissionID)
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
						sendError("PWRLVL", "You don't have a high enough power level.", conn, transmissionID)
						break
					}
					var deletedChannel Channel
					db.First(&deletedChannel, "channel_id = ?", channelMessage.ChannelID)
					if deletedChannel.ID == 0 {
						log.Warning("Channel DELETE request for nonexistant channel.")
						sendError("NOEXIST", "That channel doesn't exist.", conn, transmissionID)
						break
					}
					db.Delete(&deletedChannel)
					for _, sub := range channelSubs {
						if sub.ChannelID == channelMessage.ChannelID {
							if sub.UserID != clientInfo.UserID {
								sendError("DELETED", "The channel has been deleted.", sub.Connection, transmissionID)
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
					sendSuccess("Channel deleted successfully.", conn, transmissionID)
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
							sendError("NOACCESS", "You don't have permission to that.", conn, transmissionID)
							break
						}
					}

					if requestedChannel.ID == 0 {
						log.Warning("Client attempted subscription to nonexistant channel id " + requestedChannel.ChannelID.String())
						sendError("NOEXIST", "That channel doesn't exist.", conn, transmissionID)
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
					chanRes.MessageID = uuid.NewV4()
					chanRes.TransmissionID = transmissionID
					chanRes.Method = channelMessage.Method
					chanRes.Name = requestedChannel.Name
					chanRes.Status = "SUCCESS"
					chanRes.Type = "channelJoinRes"

					sendMessage(chanRes, conn)
				}

			case "challengeRes":
				var challengeResponse ChallengeResponse
				json.Unmarshal(msg, &challengeResponse)

				if challengeResponse.TransmissionID.String() == emptyUserID {
					sendError("VRSNERR", "You are using an unsupported client. Please upgrade.", conn, transmissionID)
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

							// give client the auth success message
							authResult := AuthResultMessage{
								MessageID:      uuid.NewV4(),
								TransmissionID: sub.TransmissionID,
								Status:         "SUCCESS",
								Type:           "authResult",
							}
							sendMessage(authResult, conn)

							// give client their user info
							clientMsg := ClientInfo{
								Type:           "clientInfo",
								Client:         clientInfo,
								MessageID:      uuid.NewV4(),
								TransmissionID: sub.TransmissionID,
							}
							sendMessage(clientMsg, conn)

							// send server welcome message
							welcomeMessage := WelcomeMessage{
								MessageID:      uuid.NewV4(),
								Type:           "welcomeMessage",
								Message:        config.WelcomeMessage,
								TransmissionID: sub.TransmissionID,
							}
							sendMessage(welcomeMessage, conn)

							// send the channel list
							sendChannelList(conn, db, clientInfo, sub.TransmissionID)

							// add to global client list
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
					sendMessage(msg, conn)
				}

				successMsg := SuccessMessage{
					Type:           "historyReqRes",
					TransmissionID: transmissionID,
					MessageID:      uuid.NewV4(),
					Status:         "SUCCESS",
				}
				sendMessage(successMsg, conn)
			case "challenge":
				// respond to challenge
				var challengeMessage ChallengeMessage
				json.Unmarshal(msg, &challengeMessage)

				var user Client
				db.First(&user, "pub_key = ?", challengeMessage.PubKey)

				fmt.Println(user)

				if challengeMessage.TransmissionID.String() == emptyUserID {
					sendError("VRSNERR", "You are using an unsupported client. Please upgrade.", conn, transmissionID)
					conn.Close()
					break
				}

				if user.ID == 0 || user.UserID.String() == emptyUserID {
					sendError("NOEXIST", "You need to register first!", conn, transmissionID)
					break
				}

				if user.Banned == true {
					sendError("BANNED", "You have been banned.", conn, transmissionID)
					conn.Close()
				}

				clientInfo = user

				var challengeResponse ChallengeResponse
				challengeResponse.Type = "challengeRes"
				challengeResponse.MessageID = uuid.NewV4()
				challengeResponse.TransmissionID = transmissionID
				challengeResponse.Response = hex.EncodeToString(ed25519.Sign(keys.Priv, []byte(challengeMessage.Challenge.String())))
				challengeResponse.PubKey = hex.EncodeToString(keys.Pub)
				sendMessage(challengeResponse, conn)

				// challenge the client
				var challengeToClient ChallengeMessage
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
				if !config.PublicRegistration {
					sendError("NOPUBRES", "Sorry, public registration isn't enabled on this server.", conn, transmissionID)
					log.Warning("Someone attempted to register, but registration is disabled.")
					return
				}

				var identityMessage IdentityMessage
				json.Unmarshal(msg, &identityMessage)

				if identityMessage.Method == "CREATE" {
					var identityResponse IdentityResponse
					identityResponse.Method = "CREATE"
					identityResponse.Type = "identityCreateRes"
					identityResponse.UUID = uuid.NewV4()
					identityResponse.MessageID = uuid.NewV4()
					identityResponse.TransmissionID = transmissionID
					identityResponse.Status = "SUCCESS"

					// create the new uuid
					db.Create(&Client{UserID: identityResponse.UUID, Username: "Anonymous", PowerLevel: 0, Banned: false})

					// send it back
					sendMessage(identityResponse, conn)
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
							var idResponse IdentityResponse
							idResponse.Type = "identityRegisterRes"
							idResponse.Method = "REGISTER"
							idResponse.TransmissionID = transmissionID
							idResponse.MessageID = uuid.NewV4()
							idResponse.Status = "SUCCESS"
							idResponse.UUID = identityMessage.UUID

							sendMessage(idResponse, conn)
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
	check(err)
}
