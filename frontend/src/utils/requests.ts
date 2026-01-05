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