import { VaasOptions } from "./VaasOptions";

export class ForStreamOptions {
  public useHashLookup: boolean;
  public vaasRequestId?: string;

  constructor(options?: { useHashLookup?: boolean; vaasRequestId?: string }) {
    this.useHashLookup = options?.useHashLookup ?? true;
    this.vaasRequestId = options?.vaasRequestId;
  }

  public static from(options: VaasOptions): ForStreamOptions {
    return new ForStreamOptions({
      useHashLookup: options.useHashLookup,
    });
  }
}
