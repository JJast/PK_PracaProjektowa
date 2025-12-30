export type WebauthnPubKeyCredParam = {
    alg: number;
    type: string;
}

export type WebauthnUser = {
    displayName: string,
    id: string,
    name: string
}

export type WebauthnRegisterOptions = {
    attestation: string,
    authenticatorSelection: {
        authenticatorAttachment: string,
        requireResidentKey: boolean,
        residentKey: string,
        userVerification: string
    },
    challenge: string,
    excludeCredentials: [],
    pubKeyCredParams: WebauthnPubKeyCredParam[],
    rp: {
        id: string,
        name: string
    },
    timeout: number,
    user: WebauthnUser
}