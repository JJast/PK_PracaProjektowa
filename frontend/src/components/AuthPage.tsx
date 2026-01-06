import React, { useRef, useState } from "react";
import SignUpForm from "./SignUpForm";
import SignInForm from "./SignInForm";
import TogglePanel from "./TogglePanel";
import { useLocation } from "react-router-dom";
import { useEffect } from "react";
import { getCsrfToken } from "../utils/requests";
import toast from "react-hot-toast";

const AuthPage: React.FC = () => {
  const [active, setActive] = useState(false);
  const csrfTokenFetched = useRef(false);
  const [csrfToken, setCsrfToken] = useState<string | null>('');

  const location = useLocation();

  useEffect(() => {
    setActive(location.pathname === "/register");
  }, [location.pathname]);

  useEffect(() => {
    (async () => {
      try {
        if (!csrfTokenFetched.current) {
          csrfTokenFetched.current = true;
          const token = await getCsrfToken();
          if (token) {
            setCsrfToken(token);
          } else {
            throw new Error("Server didn't return a valid form token!");
          }
        }
      } catch (error) {
        toast.error((error as Error).message)
      }
    })()

  }, [])

  return (
    <div className={`container ${active ? "active" : ""}`} id="container">
      <SignUpForm csrfToken={csrfToken} />
      <SignInForm csrfToken={csrfToken} />
      <TogglePanel setActive={setActive} />
    </div>
  );
};

export default AuthPage;
