package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
)

// KeyPair is a type that contains a Public and private ed25519 key.
type KeyPair struct {
	Pub  ed25519.PublicKey
	Priv ed25519.PrivateKey
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

func checkFolder() {
	progFolder := homedir + "/.vex-server"
	if !fileExists(progFolder) {
		os.Mkdir(progFolder, 0700)
	}
}

func checkKeys(cliArgs CliArgs) KeyPair {
	keyFolder := cliArgs.keyFolder

	if keyFolder == "" {
		keyFolder = homedir + "/.vex-server/keys"
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

func generateKeys() KeyPair {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	check(err)

	var keys KeyPair

	keys.Pub = pub
	keys.Priv = priv

	return keys
}
