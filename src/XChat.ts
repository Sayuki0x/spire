import { XUtils } from "@vex-chat/crypto-js";
import { XTypes } from "@vex-chat/types-js";
import cors from "cors";
import log from "electron-log";
import express from "express";
import helmet from "helmet";
import morgan from "morgan";
import nacl from "tweetnacl";
import * as uuid from "uuid";
import WebSocket from "ws";
import { ClientManager } from "./ClientManager";
import { Database } from "./Database";

export class XChat {
    private db = new Database();
    private wss = new WebSocket.Server({
        port: Number(process.env.SOCKET_PORT!),
    });
    private clients: ClientManager[] = [];
    private api = express();
    private regKeys: XTypes.HTTP.IRegKey[] = [];

    constructor() {
        this.init();
    }

    private notify(userID: string, event: string, transmissionID: string) {
        for (const client of this.clients) {
            if (client.getUser().userID === userID) {
                const msg: XTypes.WS.INotifyMsg = {
                    transmissionID,
                    type: "notify",
                    event,
                };
                client.send(msg);
            }
        }
    }

    private createRegKey(): XTypes.HTTP.IRegKey {
        const key: XTypes.HTTP.IRegKey = {
            key: uuid.v4(),
            time: new Date(Date.now()),
        };
        this.regKeys.push(key);
        return key;
    }

    private validRegKey(key: string) {
        log.info("Validating regkey: " + key);
        for (const rKey of this.regKeys) {
            if (rKey.key === key) {
                const age =
                    new Date(Date.now()).getTime() - rKey.time.getTime();
                log.info("Regkey found, " + age + " ms old.");
                if (age < 10000) {
                    log.info("Regkey is valid.");
                    this.regKeys.splice(this.regKeys.indexOf(rKey), 1);
                    return true;
                } else {
                    log.info("Regkey is expired.");
                }
            }
        }
        log.info("Regkey not found.");
    }

    private init() {
        this.wss.on("connection", (ws) => {
            log.info("New client initiated.");
            const client = new ClientManager(
                ws,
                this.db,
                this.notify.bind(this)
            );

            client.on("fail", () => {
                log.info(
                    "Client connection is down, removing: ",
                    client.toString()
                );
                if (this.clients.includes(client)) {
                    this.clients.splice(this.clients.indexOf(client), 1);
                }
                log.info("Current authorized clients: " + this.clients.length);
            });

            client.on("authed", () => {
                log.info("New client authorized: ", client.toString());
                this.clients.push(client);
                log.info("Current authorized clients: " + this.clients.length);
            });
        });

        this.api.use(express.json());
        this.api.use(helmet());

        this.api.use(morgan("dev", { stream: process.stdout }));
        this.api.use(cors());

        this.api.get("/user/:id", async (req, res) => {
            const user = await this.db.retrieveUser(req.params.id);

            if (user) {
                return res.send(user);
            } else {
                res.status(404);
            }
        });

        this.api.post("/register/key", (req, res) => {
            try {
                log.info("New regkey requested.");
                const regKey = this.createRegKey();
                log.info("New regkey created: " + regKey.key);
                return res.status(201).send(regKey);
            } catch (err) {
                log.error(err.toString());
                return res.sendStatus(500);
            }
        });

        this.api.post("/register/new", async (req, res) => {
            try {
                const regPayload: XTypes.HTTP.IRegPayload = req.body;

                if (regPayload.username.length < 3) {
                    res.status(400).send({
                        error: "Username must be at least three characters.",
                    });
                    return;
                }

                const regKey = nacl.sign.open(
                    XUtils.decodeHex(regPayload.signed),
                    XUtils.decodeHex(regPayload.signKey)
                );
                if (regKey && this.validRegKey(uuid.stringify(regKey))) {
                    const [user, err] = await this.db.createUser(
                        regKey,
                        regPayload
                    );
                    if (err !== null) {
                        switch ((err as any).code) {
                            case "ER_DUP_ENTRY":
                                log.warn(
                                    "User attempted to register duplicate account."
                                );
                                res.status(400).send({
                                    error:
                                        "Either username or public key is already taken.",
                                });
                                break;
                            default:
                                log.info(
                                    "Unsupported sql error type:",
                                    (err as any).code
                                );
                                res.sendStatus(500);
                                break;
                        }
                    } else {
                        log.info("Registration success.");
                        res.send(user);
                    }
                }
            } catch (err) {
                log.error("error registering user:", err.toString());
                res.sendStatus(500);
            }
        });

        this.api.listen(Number(process.env.API_PORT!), () => {
            log.info("API started on port", process.env.API_PORT);
        });
    }
}