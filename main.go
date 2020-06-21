package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

const version string = "v0.1.0"

type App struct {
	Router *mux.Router
}

func (a *App) Initialize() {
	router := mux.NewRouter()
	router.Handle("/", SocketHandler()).Methods("GET")
	a.Router = router
}

func main() {
	a := App{}
	a.Initialize()
	a.Run(":8000")
}

func SocketHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var upgrader = websocket.Upgrader{
			// EnableCompression: true,
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
		}

		upgrader.CheckOrigin = func(r *http.Request) bool { return true }
		conn, _ := upgrader.Upgrade(w, r, nil)
		defer conn.Close()
		fmt.Println("Connection opened!")
	})
}

func (a *App) Run(addr string) {
	http.ListenAndServe(addr, a.Router)
}
