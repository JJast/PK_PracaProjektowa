import "../styles/forms.css";

const TwoFactorAuth: React.FC = () => {

    return (
        <div>
            <h1> Two-factor authentication</h1>
            <button> Authenticate </button>

            <h2> Lost access to key?</h2>
            <p> Try a recovery code instead </p>
            <form>
                <input type="text" name="recovery" />
                <button> Submit </button>
            </form>
        </div>
    )
}
export default TwoFactorAuth;