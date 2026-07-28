export const SUNSHINE_PROTECTED_PORT_MIN = 47_984;
export const SUNSHINE_PROTECTED_PORT_MAX = 48_010;

export function isSunshineProtectedPort(port: number): boolean {
  return Number.isInteger(port)
    && port >= SUNSHINE_PROTECTED_PORT_MIN
    && port <= SUNSHINE_PROTECTED_PORT_MAX;
}

export function assertSunshinePortsUntouched(port: number, operation = "use"): void {
  if (!isSunshineProtectedPort(port)) return;
  throw new Error(
    `Refusing to ${operation} TCP/UDP port ${port}: `
      + `Sunshine's protected listener range is ${SUNSHINE_PROTECTED_PORT_MIN}-${SUNSHINE_PROTECTED_PORT_MAX}`,
  );
}
