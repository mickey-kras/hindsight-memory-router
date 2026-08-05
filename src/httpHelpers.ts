function decodePathSegment(segment: string): string {
  try {
    return decodeURIComponent(segment);
  } catch {
    throw new HttpError(
      400,
      "invalid_path_encoding",
      "path segment contains malformed percent-encoding",
    );
  }
}

export function parseMemoryPath(
  pathname: string,
): { writerId: string; action: "retain" | "recall" } | null {
  const retain = pathname.match(/^\/v1\/default\/banks\/([^/]+)\/memories$/);
  if (retain) {
    return { writerId: decodePathSegment(retain[1]), action: "retain" };
  }

  const recall = pathname.match(
    /^\/v1\/default\/banks\/([^/]+)\/memories\/recall$/,
  );
  if (recall) {
    return { writerId: decodePathSegment(recall[1]), action: "recall" };
  }

  return null;
}

export function parseAdminItemPath(pathname: string): {
  quarantineId: string;
  action: "read" | "approve" | "reject" | "postpone";
} | null {
  const match = pathname.match(
    /^\/admin\/quarantine\/items\/([^/]+)(?:\/(approve|reject|postpone))?$/,
  );
  if (!match) return null;
  return {
    quarantineId: decodePathSegment(match[1]),
    action: (match[2] ?? "read") as "read" | "approve" | "reject" | "postpone",
  };
}
