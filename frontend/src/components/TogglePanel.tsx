import React from "react";
import "../styles/toggle.css";
import { useNavigate } from "react-router-dom";

type Props = {
  setActive: (v: boolean) => void;
};

const TogglePanel: React.FC<Props> = ({ setActive }) => {
  const navigate = useNavigate();

  const handleSignIn = () => {
    setActive(false);
    navigate("/login");
  };

  const handleSignUp = () => {
    setActive(true);
    navigate("/register");
  };

  return (
    <div className="toggle-container">
      <div className="toggle">
        <div className="toggle-panel toggle-left">
          <h1>Welcome Back!</h1>
          <p>Enter your personal details to use all of site features</p>
          <button className="hidden" id="login" onClick={handleSignIn}>
            Sign In
          </button>
        </div>
        <div className="toggle-panel toggle-right">
          <h1>Hello, Friend!</h1>
          <p>Register with your personal details to use all of site features</p>
          <button className="hidden" id="register" onClick={handleSignUp}>
            Sign Up
          </button>
        </div>
      </div>
    </div>
  );
};

export default TogglePanel;
