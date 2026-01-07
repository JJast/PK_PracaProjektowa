import { API_BASE_URL } from "./constants";

export async function getCsrfToken() {
    const res = await fetch(`${API_BASE_URL}/csrf-token`, { credentials: 'include' })
    const json = await res.json()

    return json.csrf_token;
}

export function getCsrfHeaders(csrfToken: string | null) {
    const csrfObj = (csrfToken ? { "X-CSRFToken": csrfToken } : null)

    return csrfObj
}

export async function apiGet(url: string) {
  return fetch(url, {
    method: 'GET',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
    },
  });
}

export async function apiPost(url: string, body: any) {
  const tokenResponse = await fetch('/csrf-token');
  const { csrf_token } = await tokenResponse.json();

  return fetch(url, {
    method: 'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRFToken': csrf_token
    },
    body: JSON.stringify(body),
  });
}