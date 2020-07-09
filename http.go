package main

import (
	"encoding/hex"
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/ed25519"
)

func getRouter(a *App) *mux.Router {
	// initialize router
	router := mux.NewRouter()
	router.Handle("/socket", SocketHandler(a.Keys, a.Db, a.Config)).Methods("GET")
	router.Handle("/", HomeHandler(a.Keys.Pub)).Methods("GET")
	router.Handle("/status", StatusHandler(a.Keys.Pub)).Methods("GET")
	router.Handle("/file/{fileID}", FileHandler(a.Db)).Methods("GET")

	return router
}

// GetIP from http request
func GetIP(r *http.Request) string {
	forwarded := r.Header.Get("X-FORWARDED-FOR")
	if forwarded != "" {
		return forwarded
	}
	return r.RemoteAddr
}

func FileHandler(db *gorm.DB) http.Handler {
	return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		log.Info(req.Method, req.URL, GetIP(req))

		vars := mux.Vars(req)
		fileID := vars["fileID"]

		var file File

		db.First(&file, "file_id = ? ", fileID)

		if file.ID == 0 {
			log.Warning("Non existant file.")
			http.Error(res, "404 not found.", 404)
		} else {
			file := readJSONFile(FileFolder + "/" + fileID)

			res.Write(file)
		}

	})
}

// StatusHandler handles the status endpoint.
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

// HomeHandler handles the server homepage.
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
