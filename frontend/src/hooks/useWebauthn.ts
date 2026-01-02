import { useState } from "react"
import type { AuthCredential, AuthCredentialResponse, WebauthnCredential, WebauthnRegisterOptions } from "../types/webauthn"
import { decodeWebauthnOptions, encodeCredential } from "../utils/base64"
import { API_BASE_URL } from "../utils/constants"

export default function useWebAuthn() {
    const [error, setError] = useState(null);

    const getOptions = async (): Promise<WebauthnRegisterOptions> => {
        const res = await fetch(
            `${API_BASE_URL}/webauthn/register`,
            { credentials: "include" },
        )

        return (await res.json()).options
    }

    const createCredentials = async (options: WebauthnRegisterOptions): Promise<WebauthnCredential> => {
        const options_ = decodeWebauthnOptions(options);
        const credential = await navigator.credentials.create({ publicKey: options_ })

        if (!credential) {
            throw new Error("Couldn't create credentials");
        }

        // Not likely to happen but helps to narrow down the typing of credential variable
        if (!(credential instanceof PublicKeyCredential)) {
            throw new Error("Invalid type of credentials returned by create().");
        }

        return encodeCredential(credential);;
    }

    const verifyCredentials = async (
        credential: WebauthnCredential,
        action: "register" | "authenticate",
        label: string = ""
    ) => {
        const body: WebauthnCredential & { label?: string } = credential;
        if (action === "register") {
            body.label = label
        }

        const endpointUrl = `${API_BASE_URL}/webauthn/${action}/verify`;
        const res = await fetch(endpointUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
            credentials: "include"
        });

        return await res.json();
    }

    const getCredentials = async (): Promise<AuthCredentialResponse> => {
        const res = await fetch(`${API_BASE_URL}/credentials`, {
            credentials: "include",
        });

        const data = await res.json();

        if (!data || !data.credentials || !data.username) {
            throw new Error(`Received malformed data: ${JSON.stringify(data)}`);
        }

        data.credentials = data.credentials.map((cred: any): AuthCredential => {
            const { created_at: createdAt, id, key_label: keyLabel } = cred;
            return {
                createdAt, id, keyLabel
            }
        })

        return data;
    }

    return { getOptions, createCredentials, getCredentials, verifyCredentials, error, setError };
}
