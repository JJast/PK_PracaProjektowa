import React, { useState } from "react";
import { useParams, useNavigate, Link } from "react-router-dom";
import "../styles/forms.css";
import "../styles/index.css";
import { API_BASE_URL } from "../utils/constants";
import toast from "react-hot-toast";
import { getCsrfHeaders, getCsrfToken } from "../utils/requests";

const ResetPassword = () => {
  const { token } = useParams<{ token: string }>();
  const navigate = useNavigate();

  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (password !== confirmPassword) {
      toast.error("Passwords do not match!");
      return;
    }

    setLoading(true);
    const loadingToast = toast.loading("Updating password...");

    try {
      const currentToken = await getCsrfToken();
      const csrfHeaders = getCsrfHeaders(currentToken);

      const res = await fetch(`${API_BASE_URL}/reset-password/${token}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...csrfHeaders,
        },
        credentials: "include",
        body: JSON.stringify({ password }),
      });

      const data = await res.json();

      if (!res.ok) {
        toast.error(data.error || "Reset link is invalid or expired", { id: loadingToast });
      } else {
        toast.success("Password changed successfully!", { id: loadingToast });

        setTimeout(() => navigate("/login"), 2000);
      }
    } catch (err) {
      toast.error("An error occurred. Please try again.", { id: loadingToast });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="form-container container" style={{ position: 'static', margin: 'auto', opacity: 1 }}>
      <form onSubmit={handleSubmit}>
        <h1>New Password</h1>
        <p style={{ fontSize: '14px', margin: '10px 0', color: '#666' }}>
          Please enter your new password below.
        </p>

        <input
          type="password"
          placeholder="New Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
          minLength={8}
        />

        <input
          type="password"
          placeholder="Confirm New Password"
          value={confirmPassword}
          onChange={(e) => setConfirmPassword(e.target.value)}
          required
        />

        <button type="submit" disabled={loading} style={{ marginTop: '10px' }}>
          {loading ? "Updating..." : "Update Password"}
        </button>

        <div style={{ marginTop: '20px' }}>
          <Link to="/login" style={{ fontSize: '13px', color: '#333' }}>
            Back to Sign In
          </Link>
        </div>
      </form>
    </div>
  );
};

export default ResetPassword;