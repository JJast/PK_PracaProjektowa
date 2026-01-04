import React, { useState } from "react";
import "../styles/forms.css";
import { API_BASE_URL } from "../utils/constants";
import toast from "react-hot-toast";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { base64urlToArrayBuffer } from "../utils/base64";

const SignInForm: React.FC = () => {
  const navigate = useNavigate();
  const { checkAuth } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [webauthnOpts, setWebauthnOpts] = useState<any>(null);
  const [recoveryCode, setRecoveryCode] = useState<string>("");
  const [active2fa, setActive2fa] = useState(false);

  const startWebAuthnAuthentication = async (options: any) => {
    try {
      // Create assertion
      const assertion = await navigator.credentials.get({
        publicKey: {
          ...options.options,
          challenge: base64urlToArrayBuffer(options.options.challenge),
          allowCredentials: options.options.allowCredentials.map(
            (cred: any) => {
              let { _transports, ...credRest } = cred;
              return {
                ...credRest,
                id: base64urlToArrayBuffer(cred.id),
                transports: []
              }
            }
          ),
          // rpId: "localhost"
        },
      });

      if (!assertion) {
        throw new Error("WebAuthn authentication failed");
      }
      // Convert assertion to JSON for sending to server
      const authData = assertion as any;
      const response = authData.response;

      const authResult = await fetch(
        `${API_BASE_URL}/webauthn/authenticate/verify`,
        {
          method: "POST",
          credentials: "include",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            id: authData.id,
            rawId: btoa(String.fromCharCode(...new Uint8Array(authData.rawId)))
              .replace(/\+/g, "-")
              .replace(/\//g, "_")
              .replace(/=/g, ""),
            response: {
              authenticatorData: btoa(
                String.fromCharCode(
                  ...new Uint8Array(response.authenticatorData)
                )
              )
                .replace(/\+/g, "-")
                .replace(/\//g, "_")
                .replace(/=/g, ""),
              clientDataJSON: btoa(
                String.fromCharCode(...new Uint8Array(response.clientDataJSON))
              )
                .replace(/\+/g, "-")
                .replace(/\//g, "_")
                .replace(/=/g, ""),
              signature: btoa(
                String.fromCharCode(...new Uint8Array(response.signature))
              )
                .replace(/\+/g, "-")
                .replace(/\//g, "_")
                .replace(/=/g, ""),
              userHandle: response.userHandle
                ? btoa(
                  String.fromCharCode(...new Uint8Array(response.userHandle))
                )
                  .replace(/\+/g, "-")
                  .replace(/\//g, "_")
                  .replace(/=/g, "")
                : null,
            },
            type: authData.type,
          }),
        }
      );

      if (!authResult.ok) {
        throw new Error("Failed to verify WebAuthn authentication");
      }

      toast.success("Authentication successful!");
      await checkAuth();
      navigate("/dashboard");
    } catch (err) {
      console.error("WebAuthn auth error:", err);
      toast.error("WebAuthn authentication failed");
      throw err;
    }
  };

  const handleRecoverClick = async (e: React.SyntheticEvent) => {
    e.preventDefault();
    try {
      setLoading(true);
      const res = await fetch(
        `${API_BASE_URL}/webauthn/authenticate/recover`,
        {
          method: "POST",
          credentials: "include",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            "recovery_code": recoveryCode
          }),
        }
      );
      if (!res.ok) {
        throw new Error("Failed to log in using recovery code");
      }

      toast.success("Authentication successful!");
      await checkAuth();
      navigate("/dashboard");
    } catch (err) {
      toast.error(String(err));
    } finally {
      setLoading(false);
    }

  }

  const handleWebauthnClick = async () => {
    try {
      setLoading(true);
      toast.success("Waiting for second authentication factor...")
      await startWebAuthnAuthentication(webauthnOpts);
    } catch (err) {
      toast.error(String(err));
    } finally {
      setLoading(false);
    }
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE_URL}/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ username: email, password }),
      });

      const data = await res.json();

      if (!res.ok) {
        toast.error(data.error || "Login failed");
        return;
      }

      if (data.webauthn) {
        // If WebAuthn is required, get the options and start WebAuthn flow
        const optsRes = await fetch(`${API_BASE_URL}${data.next}`, {
          method: "GET",
          credentials: "include",
        });
        const opts = await optsRes.json();

        // Start WebAuthn authentication
        setActive2fa(true);
        setWebauthnOpts(opts);
        // await startWebAuthnAuthentication(opts);
      } else {
        toast.success("Login successful!");
        await checkAuth();
        navigate("/dashboard");
      }
    } catch (err) {
      toast.error(String(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="form-container sign-in">
      <form onSubmit={handleSubmit}>
        <h1>Sign In</h1>
        <input
          type="email"
          placeholder="Email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
        />
        <input
          type="password"
          placeholder="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />
        {/* <a href="#">Forget Your Password?</a> */}
        <br />
        <button type="submit" disabled={loading}>
          {loading ? "Signing in..." : "Sign In"}
        </button>
      </form>

      <div className={`sign-in-2fa ${active2fa ? "active" : ""}`}>
        <div>
          <h2> Two-factor authentication</h2>
          <p> Use your 2FA key to log in </p>
          <button onClick={handleWebauthnClick} disabled={loading}> Authenticate </button>
        </div>
        <div className="sign-in-2fa-recovery">
          <h2> Lost access to the key?</h2>
          <p> Try a recovery code instead </p>
          <form>
            <input type="text" name="recovery" onChange={(e) => { setRecoveryCode(e.target.value) }} />
            <button disabled={loading} onClick={handleRecoverClick}> Submit </button>
          </form>
        </div>
      </div>
    </div >
  );
};

export default SignInForm;
