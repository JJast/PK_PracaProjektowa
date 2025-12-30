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

  const handleAddKey = async () => {
    navigate("/register-key")
  };

  return (
    <div className="dashboard-container">
      <h1>Hello, {username}!</h1>
      <div>
        <div className="account-container">
          <h2> Account management </h2>
          <h3> Two-factor authentication </h3>
          <button onClick={handleAddKey} className="primary-button">
            Add 2FA key
          </button>
        </div>
        <button onClick={handleLogout} className="logout-button">
          Logout
        </button>
      </div>
    </div>
  );
};

export default Dashboard;
