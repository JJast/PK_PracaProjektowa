import { useState } from "react"
import type { WebauthnCredential, WebauthnRegisterOptions } from "../types/webauthn"
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
        action: "register" | "authenticate" = "authenticate"
    ) => {
        const endpointUrl = `${API_BASE_URL}/webauthn/${action}/verify`;
        const res = await fetch(endpointUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(credential),
            credentials: "include"
        });

        return await res.json();
    }

    const getCredentials = () => { }

    return { getOptions, createCredentials, getCredentials, verifyCredentials, error, setError };
}
