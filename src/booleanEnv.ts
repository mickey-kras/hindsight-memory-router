export function booleanEnv(
  environment: NodeJS.ProcessEnv,
  name: string,
  fallback: boolean,
): boolean {
  const raw = environment[name];
  if (raw === undefined) return fallback;
  if (raw === "true") return true;
  if (raw === "false") return false;
  throw new Error(`${name} must be true or false`);
}
