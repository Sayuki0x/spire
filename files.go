package main

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"os"
)

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

func readJSONFile(filename string) []byte {
	file, openErr := os.Open(filename)
	check(openErr)

	data, readErr := ioutil.ReadAll(file)
	check(readErr)

	return data
}

func writeJSONFile(filename string, data interface{}) {
	jsonBytes, parseErr := json.MarshalIndent(data, "", "   ")
	check(parseErr)

	writeErr := ioutil.WriteFile(filename, jsonBytes, 0700)
	check(writeErr)
}
