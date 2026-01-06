import React, { useState } from "react";
import "../styles/forms.css";
import { API_BASE_URL } from "../utils/constants";
import toast from "react-hot-toast";
import { Link } from "react-router-dom";
import { getCsrfHeaders } from "../utils/requests";

const ForgotPassword = () => {
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);

    try {
      const { getCsrfToken } = await import("../utils/requests");
      const currentToken = await getCsrfToken();
      const csrfHeaders = getCsrfHeaders(currentToken);

      const res = await fetch(`${API_BASE_URL}/forgot-password`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...csrfHeaders,
        },
        credentials: "include",
        body: JSON.stringify({ username: email }),
      });

      const data = await res.json();

      if (!res.ok) {
        toast.error(data.error || "Failed to send reset link");
      } else {
        toast.success(data.message || "Reset link sent to your email!");
      }
    } catch (err) {
      toast.error("An error occurred. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="form-container sign-in" style={{ position: 'static', margin: 'auto', opacity: 1 }}>
      <form onSubmit={handleSubmit}>
        <h1>Reset Password</h1>
        <p style={{ fontSize: '14px', margin: '10px 0', color: '#666' }}>
          Enter your email address and we'll send you a link to reset your password.
        </p>
        <input
          type="email"
          placeholder="Email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
        />
        <br />
        <button type="submit" disabled={loading}>
          {loading ? "Sending..." : "Send Reset Link"}
        </button>
        <Link to="/login" style={{ marginTop: '20px', fontSize: '13px', color: '#333' }}>
          Back to Sign In
        </Link>
      </form>
    </div>
  );
};

export default ForgotPassword;