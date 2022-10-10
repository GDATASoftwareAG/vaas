import WebSocket from "isomorphic-ws";

/** Connection was closed with error - Code and reason are public memebers of error.closeEvent. */
export class VaasConnectionClosedError extends Error {
  constructor(public closeEvent?: WebSocket.CloseEvent) {
    super("Connection was closed with error");
  }
}

/** Vaas authentication failed. */
export class VaasAuthenticationError extends Error {
  constructor() {
    super("Vaas authentication failed");
  }
}

/** Vaas invalid state error. */
export class VaasInvalidStateError extends Error {
  constructor(message: string) {
    super(message);
  }
}
