export class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly headers: Readonly<Record<string, string>> = {},
  ) {
    super(message);
    this.name = "HttpError";
  }
}

export function safeErrorBody(error: unknown): {
  status: number;
  body: unknown;
  headers?: Readonly<Record<string, string>>;
} {
  if (error instanceof HttpError) {
    return {
      status: error.status,
      body: { error: error.code, message: error.message },
      ...(Object.keys(error.headers).length > 0
        ? { headers: error.headers }
        : {}),
    };
  }
  return { status: 500, body: { error: "internal error" } };
}
