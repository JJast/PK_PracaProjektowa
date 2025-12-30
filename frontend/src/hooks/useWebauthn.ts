import { API_BASE_URL } from "../utils/constants"


export default function useWebauthn() {
    const getOptions = async () => {

    }

    const createCredentials = async () => {
        // const res = await fetch(
        //     `${API_BASE_URL}/webauthn/register`,
        //     {
        //         credentials: "include",
        //     })

        // const registerData = await res.json();
        // console.log(registerData.options);
        // const credential = await navigator.credentials.create({
        //     publicKey: registerData.options
        // });

        // console.log(credential);
    }

    const getCredentials = () => { }

    return { createCredentials, getCredentials };
}
