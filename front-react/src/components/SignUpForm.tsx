import React from "react";
// import SocialIcons from "./SocialIcons";
import "../styles/forms.css";

const SignUpForm: React.FC = () => (
  <div className="form-container sign-up">
    <form>
      <h1>Create Account</h1>
      {/* <SocialIcons />
      <span>or use your email for registeration</span> */}
      <input type="email" placeholder="Email" />
      <input type="password" placeholder="Password" />
      <button type="button">Sign Up</button>
    </form>
  </div>
);

export default SignUpForm;
