import React, { useState } from "react";
// import SocialIcons from "./SocialIcons";
import "../styles/forms.css";
import { API_BASE_URL } from "../utils/constants";
import toast from "react-hot-toast";

const SignUpForm: React.FC = () => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE_URL}/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ username: email, password }),
      });
      const data = await res.json();
      if (!res.ok) {
        toast.error(data.error || "Registration failed");
      } else {
        toast.success("Registered successfully.\nYou can now sign in.");
        // If server returns a 'next' endpoint (webauthn), fetch its options to verify the flow
        if (data.next) {
          const optsRes = await fetch(`${API_BASE_URL}${data.next}`, {
            method: "GET",
            credentials: "include",
          });
          const opts = await optsRes.json();
          console.log("WebAuthn options:", opts);
        }
      }
    } catch (err) {
      toast.error(String(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="form-container sign-up">
      <form onSubmit={handleSubmit}>
        <h1>Create Account</h1>
        {/* <SocialIcons />
        <span>or use your email for registeration</span> */}
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
        <button type="submit" disabled={loading}>
          {loading ? "Signing up..." : "Sign Up"}
        </button>
      </form>
    </div>
  );
};

export default SignUpForm;
