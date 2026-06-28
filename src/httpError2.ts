export class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "HttpError";
  }
}

export function httpErrorResponse(error: unknown): {
  status: number;
  body: { error: string; message: string };
} {
  if (error instanceof HttpError) {
    return {
      status: error.status,
      body: { error: error.code, message: error.message },
    };
  }
  return {
    status: 500,
    body: { error: "internal_error", message: "internal error" },
  };
}
