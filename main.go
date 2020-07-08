package main

import (
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
	Args   CliArgs
	Keys   KeyPair
	Config Config
}

func main() {
	a := App{}
	a.Initialize()
	log.Info("Starting API on port " + strconv.Itoa(a.Config.Port))
	a.Run(":" + strconv.Itoa(a.Config.Port))
}

// Initialize does the initialization of App.
func (a *App) Initialize() {
	LoggerConfig()
	a.Args = getArgs()
	printASCII()
	checkFolder()
	a.Config = readConfig(a.Args)
	a.Keys = checkKeys(a.Args)
	a.Db = getDB(a.Config)
	a.Router = getRouter(a)
}

// Run starts the vex server.
func (a *App) Run(addr string) {
	err := http.ListenAndServe(addr, a.Router)
	check(err)
}
