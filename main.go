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
	router.Handle("/socket", SocketHandler()).Methods("GET")
	a.Router = router
}

func main() {
	a := App{}
	a.Initialize()
	a.Run(":8000")
}

func SocketHandler() http.Handler {
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

			fmt.Println(string(msg))
			conn.WriteMessage(msgType, msg)
		}
	})
}

func (a *App) Run(addr string) {
	http.ListenAndServe(addr, a.Router)
}
