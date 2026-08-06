export interface IntegerEnvOptions {
  minimum?: number;
}

export function integerEnv(
  environment: NodeJS.ProcessEnv,
  name: string,
  fallback: number,
  options: IntegerEnvOptions = {},
): number {
  const raw = environment[name];
  if (raw === undefined) return fallback;
  const value = Number(raw);
  const minimum = options.minimum ?? 0;
  if (!Number.isSafeInteger(value) || value < minimum) {
    const requirement = minimum === 1 ? "a positive" : "a non-negative";
    throw new Error(`${name} must be ${requirement} integer`);
  }
  return value;
}
