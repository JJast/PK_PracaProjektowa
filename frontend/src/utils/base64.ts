import type { WebauthnRegisterOptions } from "../types/webauthn";

// Utility function to convert base64 to ArrayBuffer
export function base64ToArrayBuffer(input: string): ArrayBuffer {
    console.log('Decoding base64:', input);
    input = input.replace(/-/g, '+').replace(/_/g, '/');

    // Add missing padding:
    const pad = input.length % 4;
    if (pad) {
        input += '='.repeat(4 - pad);
    }

    var binaryString = atob(input);

    var bytes = new Uint8Array(binaryString.length);
    for (var i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}

// Utility function to convert ArrayBuffer to base64url
export function arrayBufferToBase64(buffer: ArrayBuffer) {
    var binary = '';
    var bytes = new Uint8Array(buffer);
    var len = bytes.byteLength;
    for (var i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

export function convertWebauthnOptions(webauthnOptions_: WebauthnRegisterOptions) {
    const webauthnOptions = JSON.parse(JSON.stringify(webauthnOptions_));

    return webauthnOptions;
    // if (webauthnOptions.challenge) {
    //     console.log('Decoding challenge:', webauthnOptions.challenge);
    //     webauthnOptions.challenge = base64ToArrayBuffer(webauthnOptions.challenge);
    // }

    // if (webauthnOptions.user && webauthnOptions.user.id) {
    //     console.log('Decoding user ID:', webauthnOptions.user.id);
    //     webauthnOptions.user.id = base64ToArrayBuffer(webauthnOptions.user.id);
    // }

    // if (webauthnOptions.allowCredentials) {
    //     console.log('Decoding allowCredentials:', webauthnOptions.allowCredentials);
    //     webauthnOptions.allowCredentials = webauthnOptions.allowCredentials.map(cred => ({
    //         ...cred,
    //         id: base64ToArrayBuffer(cred.id)
    //     }));
    // }

    // if (webauthnOptions.excludeCredentials) {
    //     console.log('Decoding excludeCredentials:', webauthnOptions.excludeCredentials);
    //     webauthnOptions.excludeCredentials = webauthnOptions.excludeCredentials.map(cred => ({
    //         ...cred,
    //         id: base64ToArrayBuffer(cred.id)
    //     }));
    // }
}