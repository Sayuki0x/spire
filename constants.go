package main

import (
	"os"

	"github.com/op/go-logging"
)

var globalClientList = []ConnectedClient{}
var channelSubs = []*ChannelSub{}

var homedir, _ = os.UserHomeDir()
var log *logging.Logger = logging.MustGetLogger("vex")

const version string = "2.3.1"
const emptyUserID = "00000000-0000-0000-0000-000000000000"
