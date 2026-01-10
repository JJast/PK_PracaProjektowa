import type { EncodedAuthenticatorAttestationResponse, EncodedAuthenticatorAssertionResponse, WebauthnCredential, WebauthnRegisterOptions } from "../types/webauthn";

// Utility function to convert base64 to ArrayBuffer
export function base64urlToArrayBuffer(input: string): ArrayBuffer {
    input = input.replace(/-/g, '+').replace(/_/g, '/');

    // Add missing padding:
    const pad = input.length % 4;
    if (pad) {
        input += '='.repeat(4 - pad);
    }

    let binaryString = atob(input);

    let bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}

// Utility function to convert ArrayBuffer to base64url
export function arrayBufferToBase64url(buffer: ArrayBuffer) {
    let binary = '';
    let bytes = new Uint8Array(buffer);
    let len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');  // Remove padding;
}

export function decodeWebauthnOptions(webauthnOptions: WebauthnRegisterOptions): PublicKeyCredentialCreationOptions {
    let challenge = null;
    let user: PublicKeyCredentialUserEntity | null = null;
    let excludeCredentials: PublicKeyCredentialDescriptor[] = [];

    if (webauthnOptions.challenge) {
        challenge = base64urlToArrayBuffer(webauthnOptions.challenge);
    } else {
        throw new Error("Missing key: 'challenge'");
    }

    if (webauthnOptions.user && webauthnOptions.user.id) {
        user = { ...webauthnOptions.user, id: base64urlToArrayBuffer(webauthnOptions.user.id), };
    } else {
        throw new Error("Invalid value for key 'user'.");
    }

    // FIXME?
    // if (webauthnOptions.allowCredentials) {
    //     console.log('Decoding allowCredentials:', webauthnOptions.allowCredentials);
    //     webauthnOptions.allowCredentials = webauthnOptions.allowCredentials.map(cred => ({
    //         ...cred,
    //         id: base64ToArrayBuffer(cred.id)
    //     }));
    // }

    if (webauthnOptions.excludeCredentials) {

        excludeCredentials = webauthnOptions.excludeCredentials.map(cred => {
            const { transports, ...rest } = cred;

            const converted = {
                ...rest,
                id: base64urlToArrayBuffer(cred.id),
                ...(!!transports ? { transports } : null)
            }

            return converted;
        });
    }

    return { ...webauthnOptions, ...{ challenge }, ...{ user }, excludeCredentials };
}

export function encodeCredential(credential: PublicKeyCredential): WebauthnCredential {
    const credentialBase: Pick<WebauthnCredential, "id" | "rawId" | "type" | "authenticatorAttachment"> = {
        id: credential.id,
        rawId: arrayBufferToBase64url(credential.rawId),
        type: credential.type,
        authenticatorAttachment: credential.authenticatorAttachment
    };

    // type of response returned by CredentialsContainer.create()
    if (credential.response instanceof AuthenticatorAttestationResponse) {
        const clientDataJSON = arrayBufferToBase64url(credential.response.clientDataJSON);
        const attestationObject = arrayBufferToBase64url(credential.response.attestationObject);

        const transports = credential.response.getTransports();

        const response: EncodedAuthenticatorAttestationResponse = { clientDataJSON, attestationObject, transports };

        return { ...credentialBase, response };

        // type of response returned by CredentialsContainer.get()
    } else if (credential.response instanceof AuthenticatorAssertionResponse) {

        const clientDataJSON = arrayBufferToBase64url(credential.response.clientDataJSON);
        const authenticatorData = arrayBufferToBase64url(credential.response.authenticatorData);
        const signature = arrayBufferToBase64url(credential.response.signature);

        let userHandle: string | null = null;
        if (credential.response.userHandle) {
            userHandle = arrayBufferToBase64url(credential.response.userHandle);
        }

        const response: EncodedAuthenticatorAssertionResponse = {
            clientDataJSON,
            authenticatorData,
            signature,
            //add key if 
            userHandle: userHandle ? userHandle : undefined
        };

        return { ...credentialBase, response };
    }

    throw new Error("Invalid type of credential.response field.");
}