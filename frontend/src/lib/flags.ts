/**
 * Converts an ISO 3166-1 alpha-2 country code to a Unicode flag emoji.
 * Returns empty string for invalid/empty codes.
 * Note: flag emojis render on macOS, Linux, and modern Android.
 * Windows Chrome renders letter placeholders instead of flags.
 */
export function countryFlag(code: string | undefined | null): string {
  if (!code || code.length !== 2) return '';
  const cc = code.toUpperCase();
  if (!/^[A-Z]{2}$/.test(cc)) return '';
  return String.fromCodePoint(
    0x1F1E6 + cc.charCodeAt(0) - 65,
    0x1F1E6 + cc.charCodeAt(1) - 65,
  );
}
