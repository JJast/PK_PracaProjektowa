import React from "react";
// import SocialIcons from "./SocialIcons";
import "../styles/forms.css";

const SignInForm: React.FC = () => (
  <div className="form-container sign-in">
    <form>
      <h1>Sign In</h1>
      {/* <SocialIcons /> */}
      {/* <span>or use your email password</span> */}
      <input type="email" placeholder="Email" />
      <input type="password" placeholder="Password" />
      <a href="#">Forget Your Password?</a>
      <button type="button">Sign In</button>
    </form>
  </div>
);

export default SignInForm;
