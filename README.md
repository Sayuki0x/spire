# vex-server

A websocket powered chat server, written in go. Uses ed25519 signing for user authentication. Aims to eventually provide a secure, an easy to use, end to end encrypted messaging backend for small to medium groups.

Currently supports:

- user registration
- nick changes
- public chat channels
- private chat channels
- basic moderation (kicking, banning)
- basic permission configuration

Set the power level of a user to 50 to allow kicking and banning, and to 100 to allow setting the power level of other users.

## Installing

simply download the executable with wget and run it.

```
wget https://github.com/ExtraHash/vex-server/releases/download/v0.1.0/vex-server
./vex-server
```

## Compiling From Source

```
git clone git@github.com:ExtraHash/vex-server
cd vex-server
go build
./vex-server
```

## Client

we have a reference node.js cli client [here](https://github.com/ExtraHash/vex-chat).

## Installation

1. Download the latest binary from the [releases page](https://github.com/ExtraHash/vex-server/releases)
2. Run the binary with `./vex-server`
3. Log in with a client into your server
4. Shut down the server, open the vex-server.db database file, and set your user to 100 power level (this will eventually be automated in the install process)
5. Start the server back up.
6. The server is now up and running on port 8000.

## API Documentation

Prerequisites:

- All communication with the `vex` backend takes place over a websocket connection. To interface with the API, you need a way to send and receive websocket messages to a server.
- User identity is handled by a pair of ed25519 signing keys. You will need the ability to generate, sign, and verify signatures with ed25519 keys. For JavaScript, I recommend the excellent [tweetnacl-js](https://www.npmjs.com/package/tweetnacl) library.

### Message Specification

- All messages between server and client shall be in JSON format.
- All unique keys shall be [UUID version 4](<https://en.wikipedia.org/wiki/Universally_unique_identifier#Version_4_(random)>).
- All public keys and signatures send between server and client shall be in hex encoded string format.
- All messages generated shall have a unique **transmissionID** key.
- If a message is in reply to another message, it shall include this transmissionID.
- All outbound messages from the server shall have a unique **messageID** key.
- All messages shall contain a **type** key that contains a type name in camelCase.

Here's an example of one of the simplest messages you could send to the server, a "ping" message, as well as the expected reply.

OUT:

```json
{
  "type": "ping",
  "transmissionID": "2a93b212-ea1f-4e06-bb55-2074b5633226"
}
```

IN:

```json
{
  "messageID": "4d6265c2-1314-464a-bddf-02a3e176cbbb",
  "transmissionID": "2a93b212-ea1f-4e06-bb55-2074b5633226",
  "type": "pong"
}
```

Note that the transmissionID I sent to the server was included back, along with the messageID for the outbound server message and its type.

### Registration

Before we can begin sending messages to the server, we must register an identity. Connect to the websocket server and send a message with this format:

OUT:

```json
{
  "type": "identity",
  "method": "CREATE",
  "transmissionID": "067a0d9a-cbe2-4914-b5a0-32e4fecd8065"
}
```

The server will reply with a userID that you will use to identify yourself to the server. Store this information.

IN:

```json
{
  "type": "identityCreateRes",
  "method": "CREATE",
  "status": "SUCCESS",
  "transmissionID": "067a0d9a-cbe2-4914-b5a0-32e4fecd8065",
  "messageID": "41c4c588-513e-4a53-81a9-6142b565703e",
  "uuid": "982f5a71-4eb9-454d-87ec-764f02c72136"
}
```

The user ID we need is the key **uuid** in this response. Take the uuid, and sign it with your signing key, and send it back to the server along with the signature in a message with this format. (Note this is a new transmission, so a new transmissionID is generated.)

OUT:

```json
{
  "type": "identity",
  "method": "REGISTER",
  "pubkey": "67cf96785611bf6791fe816a2c92763899e0b995a67311c4c1abefe5aad67e57",
  "signed": "306a7ffbaecd511b5f2e3f8c712fa69be13b5ec6ca7e2e1fea924d7cb17132410e8fbc8c14521b043b95af3fd126b0487bcfe8cb0d7fe9ee9457b9acdd47e10a",
  "transmissionID": "101340ef-79a4-46ce-8c4b-e4972780ee16",
  "uuid": "982f5a71-4eb9-454d-87ec-764f02c72136"
}
```

Note that the **signed** key must contain your the signature of the signed UUID, and the **pubkey** key must contain your public key, both as hex strings.

If the server verifies your signature, it will send back a success message.

IN:

```json
{
  "type": "identityRegisterRes",
  "method": "REGISTER",
  "status": "SUCCESS",
  "messageID": "200fb120-65fa-4c5d-834a-b8ee7b87cade",
  "transmissionID": "101340ef-79a4-46ce-8c4b-e4972780ee16",
  "uuid": "982f5a71-4eb9-454d-87ec-764f02c72136"
}
```

Your user is now registered and you may authenticate.

### Authentication

First, we verify the servers identity by sending them a **challenge** in this format:

OUT:

```json
{
  "type": "challenge",
  "transmissionID": "526f3683-a530-447e-8c34-73f34680cd3c",
  "challenge": "95046bc7-14d7-4fac-9d85-2ee7b66c0837",
  "pubkey": "67cf96785611bf6791fe816a2c92763899e0b995a67311c4c1abefe5aad67e57"
}
```

You must have previously registered your pubkey with the server and received a valid userID.
The server will sign the challenge, and send it back like this:

IN:

```json
{
  "type": "challengeRes",
  "transmissionID": "526f3683-a530-447e-8c34-73f34680cd3c",
  "messageID": "c6ea19d0-a479-4af1-a8c2-2a32f50fba0f",
  "response": "955720aff03be411a8e3d2509838073cac42778dfe48d38c730372c224a7da4044b859675e0ed81f38e868e306fddc8883c306cccc6e35d32a3ac6af491cf80f",
  "pubkey": "4a94fea243270f1d89de7dfaf5d165840798d963c056eac08fdc76b293b63411"
}
```

If this is the first time you've connected to the server, store its pubkey. Otherwise, make sure the stored pubkey hasn't changed which could indicate the server's identity has changed. If it has, disconnect. Verify the signature. If it does not verify, disconnect.

The server will also send you a challenge in the same format:

IN:

```json
{
  "type": "challenge",
  "transmissionID": "1aba0cb2-1bd7-4e7c-99a0-d7b9f4d81224",
  "messageID": "eadf6e2c-0535-4a09-982c-10595c70431f",
  "challenge": "49a85cc4-ea01-40e2-a9ea-80a1c7c6953d",
  "pubkey": "4a94fea243270f1d89de7dfaf5d165840798d963c056eac08fdc76b293b63411"
}
```

Note the transmissionID here is not the same as the previous challenge, because this challenge is a new transmission started by the server.

Sign the _challenge_ key with your private key and send it back to the server like this:

OUT:

```json
{
  "type": "challengeRes",
  "transmissionID": "1aba0cb2-1bd7-4e7c-99a0-d7b9f4d81224",
  "pubkey": "67cf96785611bf6791fe816a2c92763899e0b995a67311c4c1abefe5aad67e57",
  "response": "c3bb1b742b4199f6c92479ae56eb934e7f2469df6524b8194b48357222f9c4aee1ff1b2a665b002ef793c02eaf9fc6d65704ebefe846c8f8ca681feb986bdd00"
}
```

If your signature verifies and matches a registered user's pubkey, you will be sent an authResult success message as well as several other informational messages:

IN:

```json
{
  "type": "authResult",
  "status": "SUCCESS",
  "transmissionID": "1aba0cb2-1bd7-4e7c-99a0-d7b9f4d81224",
  "messageID": "e5005510-d993-40cc-bc80-c6e162138b1b"
}
```

This message indicates you have authorized successfully.

IN:

```json
{
  "type": "clientInfo",
  "transmissionID": "1aba0cb2-1bd7-4e7c-99a0-d7b9f4d81224",
  "messageID": "0602da4b-23ef-45d0-a01a-a394fb32048d",
  "client": {
    "index": 25,
    "pubkey": "67cf96785611bf6791fe816a2c92763899e0b995a67311c4c1abefe5aad67e57",
    "username": "Anonymous",
    "powerLevel": 0,
    "userID": "982f5a71-4eb9-454d-87ec-764f02c72136",
    "banned": false
  }
}
```

This message contains your client information.

IN:

```json
{
  "type": "welcomeMessage",
  "transmissionID": "1aba0cb2-1bd7-4e7c-99a0-d7b9f4d81224",
  "messageID": "f2964f78-eaaa-42e2-bdfc-d493091d218d",
  "message": "Welcome to ExtraHash's server!\nHave fun and keep it clean! :D"
}
```

This is the server's welcome message.

IN:

```json
{
  "type": "channelListResponse",
  "method": "RETRIEVE",
  "status": "SUCCESS",
  "transmissionID": "1aba0cb2-1bd7-4e7c-99a0-d7b9f4d81224",
  "messageID": "e60e1cdf-5bee-4efa-800f-1389c9ee016b",
  "channels": [
    {
      "index": 1,
      "channelID": "6eaedd5d-04b6-4be1-8532-246d98e05891",
      "admin": "be4007c7-60db-4a2b-bde4-ea41523c5c21",
      "public": true,
      "name": "lulz"
    }
  ]
}
```

This message contains all channels you have access to.

At this point, you should start sending ping messages to the server every ~10 seconds to verify the connection is still up.

OUT:

```json
{
  "type": "ping",
  "transmissionID": "2a93b212-ea1f-4e06-bb55-2074b5633226"
}
```

IN:

```json
{
  "messageID": "4d6265c2-1314-464a-bddf-02a3e176cbbb",
  "transmissionID": "2a93b212-ea1f-4e06-bb55-2074b5633226",
  "type": "pong"
}
```
