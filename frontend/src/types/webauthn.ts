export type WebauthnUser = {
    displayName: string,
    id: string,
    name: string
}

export type WebauthnRegisterOptions = Omit<PublicKeyCredentialCreationOptions, "challenge" | "user" | "excludeCredentials"> & {
    challenge: string;
    user: {
        displayName: string;
        id: string;
        name: string;
    },
    excludeCredentials: (Omit<PublicKeyCredentialDescriptor, "id"> & { id: string })[]
}

export type EncodedAuthenticatorAttestationResponse =
    // Omit<AuthenticatorAttestationResponse, "attestationObject" | "clientDataJSON"> & 
    {
        attestationObject: string;
        clientDataJSON: string;
        transports: string[];
    };

// type EncodedAuthenticatorAssertionResponse = AuthenticatorAssertionResponse;
export type EncodedAuthenticatorAssertionResponse =
    // Omit<AuthenticatorAssertionResponse,
    //     "authenticatorData" |
    //     "signature" |
    //     "userHandle" |
    //     "transports" |
    //     "clientDataJSON"
    // > &
    {
        authenticatorData: string;
        signature: string;
        userHandle?: string;
        clientDataJSON: string;
    };

export type WebauthnCredential = Omit<
    PublicKeyCredential,
    "rawId" | "response" | "toJSON" | "getClientExtensionResults"
> & {
    rawId: string;
    response: (EncodedAuthenticatorAssertionResponse | EncodedAuthenticatorAttestationResponse)
    type: string;
}

export type AuthCredentialResponse = {
    credentials: AuthCredential[];
    username: string;
}

export type AuthCredential = {
    id: number;
    keyLabel: string;
    createdAt: string;
};