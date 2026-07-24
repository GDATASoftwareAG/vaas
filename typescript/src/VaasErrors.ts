import { ProblemDetails } from "./messages/ProblemDetails";

/** Vaas authentication failed. */
export class VaasAuthenticationError extends Error {
  constructor(message?: string) {
    super(message ?? "Vaas authentication failed");
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
 * @description The server encountered an internal error.
 */
export class VaasServerError extends Error {
  constructor(message: string | ProblemDetails) {
    if (message instanceof ProblemDetails) {
      super(message.detail);
    } else {
      super(message);
    }
  }
}

/** Vaas client error.
 * @description The request is malformed or cannot be completed.
 */
export class VaasClientError extends Error {
  public problemDetails?: ProblemDetails;

  constructor(message: string | ProblemDetails) {
    if (message instanceof ProblemDetails) {
      super(message.detail);
      this.problemDetails = message;
    } else {
      super(message);
    }
  }
}
