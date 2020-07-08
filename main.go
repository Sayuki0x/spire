package main

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/mysql"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"github.com/op/go-logging"
)

// App is the main app.
type App struct {
	Router *mux.Router
	Db     *gorm.DB
	Log    *logging.Logger
	Config Config
}

func main() {
	fmt.Println(defaultConfig.DbConnectionStr)
	a := App{}
	a.Initialize()
	log.Info("Starting API on port " + strconv.Itoa(a.Config.Port))
	a.Run(":" + strconv.Itoa(a.Config.Port))
}

// Initialize does the initialization of App.
func (a *App) Initialize() {
	LoggerConfig()
	cliArgs := getArgs()
	printASCII()
	checkFolder()
	config := readConfig(cliArgs)
	keys := checkKeys(cliArgs)
	a.Db = getDB(config)
	a.Config = config

	// initialize router
	router := mux.NewRouter()
	router.Handle("/socket", SocketHandler(keys, a.Db, config)).Methods("GET")
	router.Handle("/", HomeHandler(keys.Pub)).Methods("GET")
	router.Handle("/status", StatusHandler(keys.Pub)).Methods("GET")

	a.Router = router
}

// Run starts the vex server.
func (a *App) Run(addr string) {
	err := http.ListenAndServe(addr, a.Router)
	check(err)
}

func check(e error) {
	if e != nil {
		log.Fatal(e)
	}
}
