import { useEffect, useState } from "react"
import "../styles/index.css";
import "../styles/register-key.css";
import useWebAuthn from "../hooks/useWebauthn";
import type { WebauthnRegisterOptions } from "../types/webauthn";
import { useNavigate } from "react-router-dom";

export const AddKeyPage: React.FC = () => {
    const [keyName, setKeyName] = useState("");
    const [options, setOptions] = useState<WebauthnRegisterOptions | null>(null);
    const { getOptions, createCredentials, verifyCredentials } = useWebAuthn();
    const navigate = useNavigate();

    const handleKeyNameChange = (e: React.SyntheticEvent) => {
        const target = e.target as HTMLInputElement;
        setKeyName(target.value);
    }

    const handleAddClick = async () => {
        if (keyName.length > 0 && options != null) {
            // console.log(options);

            const credential = await createCredentials(options);
            const response = await verifyCredentials(credential, "register");

            if (response.status === "ok") {
                navigate("/dashboard");
            } else {
                alert("Failed to register a key!.")
            }
        }
    }

    useEffect(() => {
        if (!options) {
            getOptions().then(options => {
                console.log(options)
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

            <button onClick={handleAddClick}> Add </button>
        </div>
    )
}