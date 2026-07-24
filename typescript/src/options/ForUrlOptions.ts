import { VaasOptions } from "./VaasOptions";

export class ForUrlOptions {
  public useHashLookup: boolean;
  public vaasRequestId?: string;

  constructor(options?: { useHashLookup?: boolean; vaasRequestId?: string }) {
    this.useHashLookup = options?.useHashLookup ?? true;
    this.vaasRequestId = options?.vaasRequestId;
  }

  public static from(options: VaasOptions): ForUrlOptions {
    return new ForUrlOptions({
      useHashLookup: options.useHashLookup,
    });
  }
}
