import WebSocket from "@d-fischer/isomorphic-ws";

/** Connection was closed with error. */
export class VaasConnectionClosedError extends Error {
  /** Code and reason for connection close. */
  public closeEvent?: WebSocket.CloseEvent;

  constructor(closeEvent?: WebSocket.CloseEvent) {
    super("Connection was closed");
    this.closeEvent = closeEvent;
  }
}

/** Vaas authentication failed. */
export class VaasAuthenticationError extends Error {
  constructor() {
    super("Vaas authentication failed");
  }
}

/** Vaas invalid state error.
 * @description These are coding errors and be prevented by the developer.
 */
export class VaasInvalidStateError extends Error {
  constructor(message: string) {
    super(message);
  }
}

/** Vaas timeout. */
export class VaasTimeoutError extends Error {
  constructor() {
    super("Timeout");
  }
}

/** Vaas server error.
 * @description These are coding errors and be prevented by the developer.
 */
export class VaasServerError extends Error {
  constructor(message: string) {
    super(message);
  }
}
