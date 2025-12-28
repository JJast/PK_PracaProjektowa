import React from "react";
import "../styles/social.css";

const SocialIcons: React.FC = () => (
  <div className="social-icons">
    <a href="#" className="icon">
      <i className="fa-brands fa-google-plus-g" />
    </a>
    <a href="#" className="icon">
      <i className="fa-brands fa-facebook-f" />
    </a>
    <a href="#" className="icon">
      <i className="fa-brands fa-github" />
    </a>
    <a href="#" className="icon">
      <i className="fa-brands fa-linkedin-in" />
    </a>
  </div>
);

export default SocialIcons;
