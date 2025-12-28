import React from "react";
import toast from "react-hot-toast";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import "../styles/dashboard.css";

const Dashboard: React.FC = () => {
  const { username, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = async () => {
    try {
      await logout();
      toast.success("Logged out successfully");
      navigate("/login");
    } catch (err) {
      toast.error(String(err));
    }
  };

  const handleAddWebauthn = async () => {
    console.log("Webauthn")
  }

  return (
    <div className="dashboard-container">
      <h1>Hello, {username}!</h1>
      <div>
        <h2> Account management </h2>
        <div className="account-container">
          <h3> Two-factor authentication </h3>
          <button onClick={handleAddWebauthn} className="primary-button">
            Add 2FA
          </button>
          <button onClick={handleLogout} className="logout-button">
            Logout
            </button>
          </div>
      </div>
    </div>
  );
};

export default Dashboard;
