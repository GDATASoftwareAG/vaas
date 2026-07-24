import { VaasOptions } from "./VaasOptions";

export class ForFileOptions {
  public useCache: boolean;
  public useHashLookup: boolean;
  public vaasRequestId?: string;

  constructor(options?: {
    useCache?: boolean;
    useHashLookup?: boolean;
    vaasRequestId?: string;
  }) {
    this.useCache = options?.useCache ?? true;
    this.useHashLookup = options?.useHashLookup ?? true;
    this.vaasRequestId = options?.vaasRequestId;
  }

  public static from(options: VaasOptions): ForFileOptions {
    return new ForFileOptions({
      useCache: options.useCache,
      useHashLookup: options.useHashLookup,
    });
  }
}
