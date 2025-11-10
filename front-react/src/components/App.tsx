import React, { useState } from "react";
import "../styles/index.css";
import SignUpForm from "./SignUpForm";
import SignInForm from "./SignInForm";
import TogglePanel from "./TogglePanel";

const App: React.FC = () => {
  const [active, setActive] = useState(false);

  return (
    <div className={`container ${active ? "active" : ""}`} id="container">
      <SignUpForm />
      <SignInForm />
      <TogglePanel setActive={setActive} />
    </div>
  );
};

export default App;
