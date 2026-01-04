import { useEffect, useRef, useState } from "react"
import "../styles/index.css";
import "../styles/register-key.css";
import useWebAuthn from "../hooks/useWebauthn";
import type { WebauthnRegisterOptions } from "../types/webauthn";
import { Link } from "react-router-dom";
import toast from "react-hot-toast";

export const AddKeyPage: React.FC = () => {
    const [keyName, setKeyName] = useState("");
    const [options, setOptions] = useState<WebauthnRegisterOptions | null>(null);
    const [recoveryCode, setRecoveryCode] = useState<string>("");
    const { getOptions, createCredentials, verifyCredentials } = useWebAuthn();

    const [buttonDisabled, setButtonDisabled] = useState(false);

    //workaround for useEffect performing a request twice when React.StrictMode is enabled
    let hasFetchedOptions = useRef(false);

    const handleKeyNameChange = (e: React.SyntheticEvent) => {
        const target = e.target as HTMLInputElement;
        setKeyName(target.value);
    }

    const handleAddClick = async () => {
        if (keyName.length > 0 && options != null) {
            try {
                setButtonDisabled(true);
                const credential = await createCredentials(options);
                const response = await verifyCredentials(credential, "register", keyName);

                if (response.status === "ok") {
                    toast.success("Successfully registered a key!");
                    setRecoveryCode(response["recovery_code"])
                    setKeyName("");
                    setButtonDisabled(false);
                } else {
                    throw new Error(`Failed to register the key!`);
                }
            } catch (err) {
                toast.error((err as Error).message);
            }

        }
    }

    useEffect(() => {
        if (!hasFetchedOptions.current) {
            hasFetchedOptions.current = true;
            console.log("FETCHING OPTIONS...")
            getOptions().then(options => {
                setOptions(options);
            });
        }
    }, []);

    return (
        <div className="container register-container">
            <h2> Register a new key </h2>
            <div>
                <label> Key label </label>
                <input
                    value={keyName}
                    type="text"
                    onChange={handleKeyNameChange}
                    placeholder='e.g. "Iphone SE", "My YubiKey"...'
                />
            </div>
            <button onClick={handleAddClick} disabled={buttonDisabled}> Add </button>

            <div className="recovery-container" style={recoveryCode.length === 0 ? { display: "none" } : {}}>
                <h3> Recovery code </h3>
                This code will help you recover the account in case of losing access to your 2FA key. <br />
                <strong>Never share this account to anyone.</strong>
                <div style={{ letterSpacing: "0.1rem", textTransform: "capitalize" }}> {recoveryCode} </div>
            </div>

            <Link to={"/dashboard"}> &lt; Return to dashboard </Link>
        </div>
    )
}