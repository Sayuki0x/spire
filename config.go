package main

import (
	"encoding/json"
	"os"

	"github.com/op/go-logging"
)

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
	Files  int `json:"files"`
}

// Config is the user supplied json config
type Config struct {
	WelcomeMessage     string        `json:"welcomeMessage"`
	DbType             string        `json:"dbType"`
	DbConnectionStr    string        `json:"dbConnectionStr"`
	PublicRegistration bool          `json:"publicRegistration"`
	Port               int           `json:"port"`
	MaxUsernameLength  int           `json:"maxUsernameLength"`
	PowerLevels        RequiredPower `json:"powerLevels"`
}

var defaultConfig = Config{
	DbType:             "sqlite3",
	DbConnectionStr:    homedir + "/.vex-server/vex-server.db",
	PublicRegistration: true,
	Port:               8000,
	MaxUsernameLength:  10,
	PowerLevels: RequiredPower{
		Kick:   25,
		Ban:    50,
		Op:     100,
		Grant:  50,
		Revoke: 50,
		Talk:   0,
		Create: 50,
		Delete: 50,
		Files:  25,
	},
}

func readConfig(cliArgs CliArgs) Config {
	configPath := cliArgs.configPath

	if configPath == "" {
		configPath = homedir + "/.vex-server/config.json"
	}

	if !fileExists(configPath) {
		writeJSONFile(configPath, defaultConfig)
	}

	configBytes := readJSONFile(configPath)
	var config Config
	json.Unmarshal(configBytes, &config)

	return config
}

// LoggerConfig sets up the logger configuration.
func LoggerConfig() {
	//initialize logger
	var format = logging.MustStringFormatter(
		`%{color}%{time:15:04:05.000} ▶ %{level:.4s}%{color:reset} %{message}`,
	)
	backend := logging.NewLogBackend(os.Stderr, "", 0)
	backendFormatter := logging.NewBackendFormatter(backend, format)
	logging.SetBackend(backendFormatter)
}
