# vex-server

A websocket powered chat server, written in go. Uses ed25519 signing for user authentication. Aims to eventually provide a secure, an easy to use, end to end encrypted messaging backend for small to medium groups.

## installing

simply download the executable with wget and run it.

```
wget https://github.com/ExtraHash/vex-server/releases/download/v0.1.0/vex-server
./vex-server
```

## compiling from source

```
git clone git@github.com:ExtraHash/vex-server
cd vex-server
go build
./vex-server
```

## client

we have a reference node.js cli client [here](https://github.com/ExtraHash/vex-chat).
