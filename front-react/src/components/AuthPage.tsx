import React, { useState } from "react";
import SignUpForm from "./SignUpForm";
import SignInForm from "./SignInForm";
import TogglePanel from "./TogglePanel";
import { useLocation } from "react-router-dom";
import { useEffect } from "react";

const AuthPage: React.FC = () => {
  const [active, setActive] = useState(false);
  const location = useLocation();

  useEffect(() => {
    setActive(location.pathname === "/register");
  }, [location.pathname]);

  return (
    <div className={`container ${active ? "active" : ""}`} id="container">
      <SignUpForm />
      <SignInForm />
      <TogglePanel setActive={setActive} />
    </div>
  );
};

export default AuthPage;
