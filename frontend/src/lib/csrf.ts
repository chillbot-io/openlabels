const CSRF_COOKIE_NAME = 'openlabels_csrf';

export function getCsrfToken(): string | undefined {
  const match = document.cookie
    .split('; ')
    .find((row) => row.startsWith(`${CSRF_COOKIE_NAME}=`));
  if (!match) return undefined;
  // Use indexOf + slice to handle cookie values that contain '=' characters
  const eqIndex = match.indexOf('=');
  return eqIndex >= 0 ? match.slice(eqIndex + 1) : undefined;
}
