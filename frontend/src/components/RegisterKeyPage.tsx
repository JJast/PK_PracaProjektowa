import { useState } from "react"
import "../styles/index.css";
import "../styles/register-key.css";

export const RegisterKeyPage: React.FC = () => {
    const [keyName, setKeyName] = useState("");

    const handleKeyNameChange = (e: React.SyntheticEvent) => {
        const target = e.target as HTMLInputElement;
        console.log(`change state to ${target.value}`)
        setKeyName(target.value);
    }

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


            <button> Add </button>
        </div>
    )
}