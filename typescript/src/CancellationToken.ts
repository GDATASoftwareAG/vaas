export class CancellationToken {
    private readonly _timeout: number;

    private constructor(timeout: number) {
        this._timeout = timeout;
    }

    public timeout(): number {
        return this._timeout;
    }

    public static fromSeconds(seconds: number): CancellationToken {
        return new CancellationToken(seconds * 1000);
    }

    public static fromMinutes(minutes: number): CancellationToken {
        return new CancellationToken(minutes * 60 * 1000);
    }

    public static fromMilliseconds(milliseconds: number): CancellationToken {
        return new CancellationToken(milliseconds);
    }
}