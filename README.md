# vex-server

A websocket powered chat server, written in go. Uses ed25519 signing for user authentication. Aims to eventually provide a secure, an easy to use, end to end encrypted messaging backend for small to medium groups.

Currently supports:

- user registration
- nick changes
- public chat channels
- private chat channels
- basic moderation (kicking, banning)
- basic permission configuration

You can set the power levels required for various moderation actions in the `config.json` file.

## Installing

simply download the executable and run it.

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

# API Documentation

Prerequisites:

- All communication with the `vex` backend takes place over a websocket connection. To interface with the API, you need a way to send and receive websocket messages to a server.
- User identity is handled by a pair of ed25519 signing keys. You will need the ability to generate, sign, and verify signatures with ed25519 keys. For JavaScript, I recommend the excellent [tweetnacl-js](https://www.npmjs.com/package/tweetnacl) library.

## Message Specification

- All messages between server and client shall be in JSON format.
- All unique keys shall be [UUID version 4](<https://en.wikipedia.org/wiki/Universally_unique_identifier#Version_4_(random)>).
- All operations shall be based on the [CRUD model](https://en.wikipedia.org/wiki/Create,_read,_update_and_delete).
- All public keys and signatures send between server and client shall be in hex encoded string format.
- All messages generated shall have a unique **transmissionID** key.
- If a message is in reply to another message, it shall include this transmissionID.
- All outbound messages from the server shall have a unique **messageID** key.
- All messages shall contain a **type** key that contains a type name in camelCase.

Here's an example of one of the simplest messages you could send to the server, a "ping" message, as well as the expected reply.

#### OUT:

```json
{
  "type": "ping",
  "transmissionID": "2a93b212-ea1f-4e06-bb55-2074b5633226"
}
```

#### IN:

```json
{
  "type": "pong",
  "transmissionID": "2a93b212-ea1f-4e06-bb55-2074b5633226",
  "messageID": "4d6265c2-1314-464a-bddf-02a3e176cbbb"
}
```

Note that the transmissionID I sent to the server was included back, along with the messageID for the outbound server message and its type.

## Registration

Before we can begin sending messages to the server, we must register an identity. Connect to the websocket server and send a message with this format:

#### OUT:

```json
{
  "type": "identity",
  "method": "CREATE",
  "transmissionID": "067a0d9a-cbe2-4914-b5a0-32e4fecd8065"
}
```

The server will reply with a userID that you will use to identify yourself to the server. Store this information.

#### IN:

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

#### OUT:

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

#### IN:

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

## Authentication

First, we verify the servers identity by sending them a **challenge** in this format:

#### OUT:

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

#### IN:

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

#### IN:

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

#### OUT:

```json
{
  "type": "challengeRes",
  "transmissionID": "1aba0cb2-1bd7-4e7c-99a0-d7b9f4d81224",
  "pubkey": "67cf96785611bf6791fe816a2c92763899e0b995a67311c4c1abefe5aad67e57",
  "response": "c3bb1b742b4199f6c92479ae56eb934e7f2469df6524b8194b48357222f9c4aee1ff1b2a665b002ef793c02eaf9fc6d65704ebefe846c8f8ca681feb986bdd00"
}
```

If your signature verifies and matches a registered user's pubkey, you will be sent an authResult success message as well as several other informational messages:

#### IN:

```json
{
  "type": "authResult",
  "status": "SUCCESS",
  "transmissionID": "1aba0cb2-1bd7-4e7c-99a0-d7b9f4d81224",
  "messageID": "e5005510-d993-40cc-bc80-c6e162138b1b"
}
```

This message indicates you have authorized successfully.

#### IN:

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

#### IN:

```json
{
  "type": "welcomeMessage",
  "transmissionID": "1aba0cb2-1bd7-4e7c-99a0-d7b9f4d81224",
  "messageID": "f2964f78-eaaa-42e2-bdfc-d493091d218d",
  "message": "Welcome to ExtraHash's server!\nHave fun and keep it clean! :D"
}
```

This is the server's welcome message.

#### IN:

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

#### OUT:

```json
{
  "type": "ping",
  "transmissionID": "2a93b212-ea1f-4e06-bb55-2074b5633226"
}
```

#### IN:

```json
{
  "messageID": "4d6265c2-1314-464a-bddf-02a3e176cbbb",
  "transmissionID": "2a93b212-ea1f-4e06-bb55-2074b5633226",
  "type": "pong"
}
```

## General Server Messages

There are two types of general server messages your client may receive from the server.

### serverMsg

Messages of type serverMsg are intended to have the **message** key displayed to the user as a notification of some kind.

#### IN:

```json
{
  "type": "serverMessage",
  "message": "Channel deleted successfully.",
  "transmissionID": "3cac0763-7dbe-47f4-9cab-15635ee97791",
  "messageID": "d04cf2d9-de1a-40f0-9b62-460b409c07d0"
}
```

### errorMsg

Message of type error indicate an error occurred with the request, and will contain a code and a message to display to the user, and possibly an error object.

#### IN:

```json
{
  "transmissionID": "1ac7a4bc-2879-4eb1-bb6c-2b79c41e48e8",
  "messageID": "fcb10d42-36ea-4a60-a2d2-882e12bc2289",
  "type": "error",
  "code": "PWRLVL",
  "message": "You don't have a high enough power level.",
  "error": null
}
```

## Channels

You can send a message of type **channel** to perform operations on channels.

### CREATE

#### OUT:

```json
{
  "type": "channel",
  "method": "CREATE",
  "name": "test",
  "privateChannel": true,
  "transmissionID": "7046fdd4-8659-4940-b76e-0ad2ebac190c"
}
```

Set the privateChannel key depending on if you want the channel to be private or public.
If successful, the server will send back the channel list in response:

#### IN:

```json
{
  "type": "channelListResponse",
  "method": "RETRIEVE",
  "status": "SUCCESS",
  "transmissionID": "7046fdd4-8659-4940-b76e-0ad2ebac190c",
  "messageID": "8bc0d0e3-2d12-4936-aea3-890db40845b2",
  "channels": [
    {
      "index": 1,
      "channelID": "6eaedd5d-04b6-4be1-8532-246d98e05891",
      "admin": "be4007c7-60db-4a2b-bde4-ea41523c5c21",
      "public": true,
      "name": "lulz"
    },
    {
      "index": 2,
      "channelID": "e0af542a-a2ee-4186-9f55-a61f0eeaecf0",
      "admin": "be4007c7-60db-4a2b-bde4-ea41523c5c21",
      "public": false,
      "name": "test"
    }
  ]
}
```

### RETRIEVE

#### OUT:

```json
{
  "type": "channel",
  "method": "RETRIEVE",
  "transmissionID": "f063b123-9f18-42c6-8f4d-38f951488619"
}
```

The server will respond with type channelListResponse

#### IN:

```json
{
  "type": "channelListResponse",
  "method": "RETRIEVE",
  "status": "SUCCESS",
  "transmissionID": "7046fdd4-8659-4940-b76e-0ad2ebac190c",
  "messageID": "8bc0d0e3-2d12-4936-aea3-890db40845b2",
  "channels": [
    {
      "index": 1,
      "channelID": "6eaedd5d-04b6-4be1-8532-246d98e05891",
      "admin": "be4007c7-60db-4a2b-bde4-ea41523c5c21",
      "public": true,
      "name": "lulz"
    },
    {
      "index": 2,
      "channelID": "e0af542a-a2ee-4186-9f55-a61f0eeaecf0",
      "admin": "be4007c7-60db-4a2b-bde4-ea41523c5c21",
      "public": false,
      "name": "test"
    }
  ]
}
```

### DELETE

#### OUT:

```json
{
  "type": "channel",
  "method": "DELETE",
  "channelID": "e0af542a-a2ee-4186-9f55-a61f0eeaecf0",
  "transmissionID": "3cac0763-7dbe-47f4-9cab-15635ee97791"
}
```

If successful, the server will respond with a message of type serverMsg

```json
{
  "type": "serverMessage",
  "message": "Channel deleted successfully.",
  "transmissionID": "3cac0763-7dbe-47f4-9cab-15635ee97791",
  "messageID": "d04cf2d9-de1a-40f0-9b62-460b409c07d0"
}
```

### JOIN

Joins a channel, subscribes to messages from it.

#### OUT:

```json
{
  "type": "channel",
  "channelID": "6eaedd5d-04b6-4be1-8532-246d98e05891",
  "method": "JOIN",
  "transmissionID": "2657440b-3329-45e3-b40b-43324f07a914"
}
```

#### IN:

```json
{
  "type": "channelJoinRes",
  "method": "JOIN",
  "status": "SUCCESS",
  "channelID": "6eaedd5d-04b6-4be1-8532-246d98e05891",
  "messageID": "2a6ecc67-027d-4fae-98cf-ac487bd1d9ee",
  "transmissionID": "2657440b-3329-45e3-b40b-43324f07a914",
  "name": "lulz"
}
```

### LEAVE

Leaves a channel, removes subscription of messages from it.

#### OUT:

```json
{
  "type": "channel",
  "method": "LEAVE",
  "channelID": "6eaedd5d-04b6-4be1-8532-246d98e05891",
  "transmissionID": "5a107762-59f0-45bb-8ea3-6dabd8853664"
}
```

#### IN:

```json
{
  "type": "channelLeaveMsgRes",
  "method": "LEAVE",
  "channelID": "6eaedd5d-04b6-4be1-8532-246d98e05891",
  "messageID": "4d0478af-31df-46d6-b48f-65fe00a1c4d9",
  "transmissionID": "5a107762-59f0-45bb-8ea3-6dabd8853664",
  "privateChannel": false,
  "name": ""
}
```

The name field will always be empty in this response.

## Users

You can send a message of type **user** to perform operations on users.

### CREATE

See previous section on registration.

### RETRIEVE

Allows you to search for a userID with a username and a 4 digit hex tag, which is the second group of characters in their userID:

username: xaz
uuid: 03691084-**035e**-4da7-8992-2799d81b66cd
hex tag: 035e

#### OUT:

```json
{
  "type": "userInfo",
  "method": "RETRIEVE",
  "transmissionID": "7045bce4-9a49-4325-9e89-85c00cc95658",
  "userTag": "035e",
  "username": "xaz"
}
```

#### IN:

It will reply with the matched user list, which is an array of users.

```json
{
  "type": "userInfoRes",
  "method": "RETRIEVE",
  "transmissionID": "7045bce4-9a49-4325-9e89-85c00cc95658",
  "messageID": "274d6f85-7460-43da-96e8-126c178cf607",
  "matchList": [
    {
      "index": 20,
      "pubkey": "bed7106afd77e0f92fa5aee5e29a921647582b7e38bb8cd479aed0ddd17f11eb",
      "username": "xaz",
      "powerLevel": 50,
      "userID": "03691084-035e-4da7-8992-2799d81b66cd",
      "banned": false
    }
  ]
}
```

### UPDATE

#### OUT:

```json
{
  "type": "user",
  "method": "UPDATE",
  "transmissionID": "bb631911-3b12-4414-8c23-d9789aa49a9d",
  "powerLevel": 25,
  "userID": "03691084-035e-4da7-8992-2799d81b66cd"
}
```

Currently the only mutable value is the powerLevel.

#### IN:

```json
{
  "type": "serverMessage",
  "transmissionID": "bb631911-3b12-4414-8c23-d9789aa49a9d",
  "messageID": "ad66ae14-9614-49e4-8acf-ce8e970c1f83",
  "message": "Client has been mutated."
}
```

### DELETE

Not currently implemented, modify the database manually.

### KICK

Kicks a user (disconnects from server)

#### OUT:

```json
{
  "type": "user",
  "method": "KICK",
  "transmissionID": "bfc821bd-2e78-4e32-8abc-fdce837d1987",
  "userID": "d3cff3b0-33fd-4547-b4c0-2896a2939fdf"
}
```

#### IN:

```json
{
  "type": "serverMessage",
  "transmissionID": "bfc821bd-2e78-4e32-8abc-fdce837d1987",
  "messageID": "0d8ec274-1d82-4af3-9234-ade57c47dbfa",
  "message": "You have kicked user d3cff3b0-33fd-4547-b4c0-2896a2939fdf"
}
```

### BAN

Bans a user (permanently bans public key from accessing server)

#### OUT:

```json
{
  "type": "user",
  "method": "BAN",
  "transmissionID": "e56c5b95-1196-4ba2-89f9-5c3b8b0b60be",
  "userID": "d3cff3b0-33fd-4547-b4c0-2896a2939fdf"
}
```

#### IN:

```json
{
  "type": "serverMessage",
  "transmissionID": "e56c5b95-1196-4ba2-89f9-5c3b8b0b60be",
  "messageID": "0d8ec274-1d82-4af3-9234-ade57c47dbfa",
  "message": "You have kicked user d3cff3b0-33fd-4547-b4c0-2896a2939fdf"
}
```

### NICK

The user can only perform this operation for himself. The channelID field is optional, but if included will send a notification of the name change in that channel.

#### OUT:

```json
{
  "type": "user",
  "method": "NICK",
  "channelID": "6eaedd5d-04b6-4be1-8532-246d98e05891",
  "transmissionID": "1f0b8425-3f60-4acb-8c83-2e586d00b845",
  "username": "test"
}
```

#### IN:

The server will respond with your updated user information:

```json
{
  "type": "clientInfo",
  "transmissionID": "1f0b8425-3f60-4acb-8c83-2e586d00b845",
  "messageID": "3a3d6fc6-04d8-4e65-a651-c33a56c26233",
  "client": {
    "index": 12,
    "pubkey": "518dcccf88f0d89cc5220a601b19136fb86dec6058e6ab5f803c27b97bddcbf5",
    "username": "test",
    "powerLevel": 100,
    "userID": "be4007c7-60db-4a2b-bde4-ea41523c5c21",
    "banned": false
  }
}
```

## channelPerms

You can send a message of type **channel** to perform operations on channel permissions. If a room is marked private, the user needs to have a permission added in order to access it.

### CREATE

Creates a permission for a user.

#### OUT:

```json
{
  "type": "channelPerm",
  "method": "CREATE",
  "permission": {
    "channelID": "e1c2cd92-b2e2-4afb-a405-efc65f20df68",
    "powerLevel": 0,
    "userID": "d3cff3b0-33fd-4547-b4c0-2896a2939fdf"
  },
  "transmissionID": "af455c20-a290-4b50-aaa5-6955726d3ba1"
}
```

#### IN:

```json
{
  "type": "serverMessage",
  "transmissionID": "af455c20-a290-4b50-aaa5-6955726d3ba1",
  "messageID": "f19ed1dc-7044-48fb-b46d-4f1493490bf7",
  "message": "Permission added successfully."
}
```

### RETRIEVE

Not implemented. You may retrieve a channel list with your authorized channel information, see channel section.

### UPDATE

Not yet implemented.

### DELETE

Deletes a permission. Use this to revoke access to a channel. Will also kick the user if they are logged in.
The powerLevel is not required.

#### OUT:

```json
{
  "type": "channelPerm",
  "method": "DELETE",
  "permission": {
    "channelID": "e1c2cd92-b2e2-4afb-a405-efc65f20df68",
    "powerLevel": 0,
    "userID": "d3cff3b0-33fd-4547-b4c0-2896a2939fdf"
  },
  "transmissionID": "da98bec9-2c6f-411a-a2e0-fb2415589b90"
}
```

#### IN:

```json
{
  "type": "serverMessage",
  "transmissionID": "da98bec9-2c6f-411a-a2e0-fb2415589b90",
  "messageID": "b50af738-af68-4e39-bfd7-29bd18065c80",
  "message": "You have revoked permission for user d3cff3b0-33fd-4547-b4c0-2896a2939fdf"
}
```

## historyReq

The message of type historyReq can be sent to the server to request history forwards from a known chat message ID.

#### OUT

```json
{
  "type": "historyReq",
  "method": "RETRIEVE",
  "channelID": "6eaedd5d-04b6-4be1-8532-246d98e05891",
  "topMessage": "26c81ec2-b066-4535-b5fe-0560654fd07c",
  "transmissionID": "749c3f77-c6bd-4e54-8714-934847b76946"
}
```

The server will send all messages to you as chat messages from that point in the channel, and then reply this when finished:

```json
{
  "type": "historyReqRes",
  "status": "SUCCESS",
  "transmissionID": "749c3f77-c6bd-4e54-8714-934847b76946",
  "messageID": "9d34d5c1-fe3c-4bec-be41-58efe3ba6f0e"
}
```

##
