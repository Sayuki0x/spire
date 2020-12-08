import { sleep } from "@extrahash/sleep";
import { xConcat, XUtils } from "@vex-chat/crypto-js";
import { XTypes } from "@vex-chat/types-js";
import chalk from "chalk";
import log from "electron-log";
import { EventEmitter } from "events";
import msgpack from "msgpack-lite";
import nacl from "tweetnacl";
import {
    parse as uuidParse,
    v4 as uuidv4,
    validate as uuidValidate,
} from "uuid";
import WebSocket from "ws";
import { Database } from "./Database";
import { createUint8UUID } from "./utils/createUint8UUID";

log.transports.console.level = "info";
console.log = log.log;
console.error = log.error;

function emptyHeader() {
    return new Uint8Array(32);
}

function unpackMessage(msg: Buffer): [Uint8Array, XTypes.WS.IBaseMsg] {
    const msgp = Uint8Array.from(msg);

    const msgh = msgp.slice(0, 32);
    const msgb = msgpack.decode(msgp.slice(32));

    return [msgh, msgb];
}

function packMessage(msg: any, header?: Uint8Array) {
    const msgb = Uint8Array.from(msgpack.encode(msg));
    const msgh = header || emptyHeader();
    return xConcat(msgh, msgb);
}

export class ClientManager extends EventEmitter {
    private authed: boolean = false;
    private alive: boolean = true;
    private conn: WebSocket;
    private challengeID: Uint8Array = createUint8UUID();
    private failed: boolean = false;
    private db: Database;
    private user: XTypes.SQL.IUser | null;
    private notify: (
        userID: string,
        event: string,
        transmissionID: string
    ) => void;

    constructor(
        ws: WebSocket,
        db: Database,
        notify: (userID: string, event: string, transmissionID: string) => void
    ) {
        super();
        this.conn = ws;
        this.db = db;
        this.user = null;
        this.notify = notify;

        this.initListeners();
        this.challenge();
    }

    public toString() {
        if (!this.user) {
            return "Unauthorized#0000";
        }
        return this.user.username + "#" + this.user.userID.slice(0, 4);
    }

    public getUser(): XTypes.SQL.IUser {
        if (!this.authed) {
            throw new Error("You must be authed before getting user info.");
        }
        return this.user!;
    }

    public async send(msg: any, header?: Uint8Array) {
        if (header) {
            log.debug(chalk.red.bold("OUTH"), header.toString());
        } else {
            log.debug(chalk.red.bold("OUTH"), emptyHeader.toString());
        }

        log.debug(chalk.red.bold("OUT"), msg);
        this.conn.send(packMessage(msg, header));
    }

    private authorize(transmissionID: string) {
        this.authed = true;
        this.sendAuthedMessage(transmissionID);
        this.emit("authed");
    }

    private fail() {
        if (this.failed) {
            return;
        }
        log.warn("Connection failed.");
        if (this.conn) {
            this.conn.close();
        }
        this.failed = true;
        this.emit("fail");
    }

    private setAlive(status: boolean) {
        this.alive = status;
    }

    private async pingLoop() {
        while (true) {
            this.ping();
            await sleep(5000);
        }
    }

    private ping() {
        if (!this.alive) {
            this.fail();
            return;
        }
        this.setAlive(false);
        const p = { transmissionID: uuidv4(), type: "ping" };
        this.send(p);
    }

    private pong(transmissionID: string) {
        const p = { transmissionID, type: "pong" };
        this.send(p);
    }

    private async verifyResponse(msg: XTypes.WS.IRespMsg) {
        const user = await this.db.retrieveUser(msg.userID);
        if (user) {
            const message = nacl.sign.open(
                msg.signed,
                XUtils.decodeHex(user.signKey)
            );
            if (message) {
                if (XUtils.bytesEqual(this.challengeID, message)) {
                    this.user = user;
                    this.authorize(msg.transmissionID);
                }
            } else {
                log.info("Signature verification failed!");
                this.fail();
            }
        } else {
            log.info("User is not registered.");
            this.fail();
        }
    }

    private challenge() {
        this.challengeID = new Uint8Array(uuidParse(uuidv4()));
        const challenge: XTypes.WS.IChallMsg = {
            transmissionID: uuidv4(),
            type: "challenge",
            challenge: this.challengeID,
        };
        this.send(challenge);
    }

    private sendErr(transmissionID: string, message: string) {
        const error: XTypes.WS.IErrMsg = {
            transmissionID,
            type: "error",
            error: message,
        };
        this.send(error);
    }

    private sendAuthedMessage(transmissionID: string) {
        this.send({ type: "authorized", transmissionID });
    }

    private sendSuccess(
        transmissionID: string,
        data: any,
        header?: Uint8Array
    ) {
        const msg: XTypes.WS.ISucessMsg = {
            transmissionID,
            type: "success",
            data,
        };
        this.send(msg, header);
    }

    private async parseResourceMsg(
        msg: XTypes.WS.IResourceMsg,
        header: Uint8Array
    ) {
        switch (msg.resourceType) {
            case "otk":
                if (msg.action === "RETRIEVE") {
                    try {
                        const keyCount = await this.db.getOTKCount(
                            this.getUser().userID
                        );
                        this.sendSuccess(msg.transmissionID, keyCount);
                    } catch (err) {
                        log.error(err);
                        this.sendErr(msg.transmissionID, err.toString());
                    }
                }
                if (msg.action === "CREATE") {
                    try {
                        await this.db.saveOTK(
                            this.getUser().userID,
                            msg.data as XTypes.WS.IPreKeys
                        );
                        this.sendSuccess(msg.transmissionID, msg);
                    } catch (err) {
                        log.error(err);
                        this.sendErr(msg.transmissionID, err.toString());
                    }
                }
                break;
            case "user":
                if (msg.action === "RETRIEVE") {
                    try {
                        const user = await this.db.retrieveUser(msg.data);
                        if (user) {
                            this.sendSuccess(msg.transmissionID, user);
                        } else {
                            log.error("User doesn't exist.");
                            this.sendErr(
                                msg.transmissionID,
                                "That user doesn't exist."
                            );
                        }
                    } catch (err) {
                        log.error(err);
                        this.sendErr(msg.transmissionID, err.toString());
                    }
                }
                break;
            case "users":
                if (msg.action === "RETRIEVE") {
                    try {
                        const users = await this.db.retrieveUsers();
                        this.sendSuccess(msg.transmissionID, users);
                    } catch (err) {
                        log.error(err);
                        this.sendErr(msg.transmissionID, err.toString());
                    }
                }
                break;
            case "keyBundle":
                if (msg.action === "RETRIEVE") {
                    try {
                        const keyBundle = await this.db.getKeyBundle(msg.data);
                        if (keyBundle) {
                            this.sendSuccess(msg.transmissionID, keyBundle);
                        } else {
                            this.sendErr(
                                msg.transmissionID,
                                "Couldn't retrieve key bundle."
                            );
                        }
                    } catch (err) {
                        log.error(err);
                        this.sendErr(msg.transmissionID, err.toString());
                    }
                }
                break;
            case "mail":
                if (msg.action === "RETRIEVE") {
                    try {
                        const inbox = await this.db.retrieveMail(
                            this.getUser().userID
                        );
                        for (const mail of inbox) {
                            const [mailHeader, mailBody] = mail;
                            this.sendSuccess(
                                msg.transmissionID,
                                mailBody,
                                mailHeader
                            );
                        }
                        this.sendSuccess(msg.transmissionID, null);
                    } catch (err) {
                        log.error(err);
                        this.sendErr(msg.transmissionID, err.toString());
                    }
                }
                if (msg.action === "CREATE") {
                    try {
                        await this.db.saveMail(
                            msg.data,
                            header,
                            this.getUser().userID
                        );
                        log.info("Received mail for " + msg.data.recipient);
                        this.sendSuccess(msg.transmissionID, null);
                        this.notify(
                            msg.data.recipient,
                            "mail",
                            msg.transmissionID
                        );
                    } catch (err) {
                        log.error(err);
                        this.sendErr(msg.transmissionID, err.toString());
                    }
                }
                break;
            default:
                log.info("Unsupported resource type " + msg.resourceType);
        }
    }

    private async handleReceipt(msg: XTypes.WS.IReceiptMsg) {
        await this.db.deleteMail(msg.nonce, this.getUser().userID);
    }

    private initListeners() {
        this.conn.on("open", () => {
            this.pingLoop();
        });
        this.conn.on("close", () => {
            this.fail();
        });
        this.conn.on("message", (message: Buffer) => {
            const [header, msg] = unpackMessage(message);

            log.debug(chalk.red.bold("INH"), header.toString());
            log.debug(chalk.red.bold("IN"), msg);

            if (!msg.type) {
                this.sendErr(msg.transmissionID, "Message type is required.");
                return;
            }

            if (!uuidValidate(msg.transmissionID)) {
                this.sendErr(
                    uuidv4(),
                    "transmissionID is required and must be a valid uuid."
                );
                return;
            }

            switch (msg.type) {
                case "receipt":
                    this.handleReceipt(msg as XTypes.WS.IReceiptMsg);
                    break;
                case "resource":
                    if (!this.authed) {
                        this.sendErr(
                            msg.transmissionID,
                            "You are not authenticated."
                        );
                        break;
                    }
                    this.parseResourceMsg(
                        msg as XTypes.WS.IResourceMsg,
                        header
                    );
                    break;
                case "response":
                    this.verifyResponse(msg as XTypes.WS.IRespMsg);
                    break;
                case "ping":
                    this.pong(msg.transmissionID);
                    break;
                case "pong":
                    this.setAlive(true);
                    break;
                default:
                    log.info("unsupported message %s", msg.type);
                    break;
            }
        });
    }
}