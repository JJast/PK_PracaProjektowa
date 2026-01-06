import React, { useEffect, useState } from "react";
import toast from "react-hot-toast";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import "../styles/dashboard.css";
import useWebAuthn from "../hooks/useWebauthn";
import type { AuthCredential, AuthCredentialResponse } from "../types/webauthn";

const CredentialItem = ({ cred }: { cred: AuthCredential }) => {
  return (
    <div style={{ textAlign: "left" }} className="credential-item">
      <h4>{cred.keyLabel}</h4>
      <hr />
      <div>
        <i>id: {cred.id}</i>
      </div>
      <div>Created at: {cred.createdAt}</div>
    </div>
  );
};

const Dashboard: React.FC = () => {
  const { username, logout } = useAuth();
  const navigate = useNavigate();

  const { getCredentials } = useWebAuthn();
  const [credentials, setCredentials] = useState<AuthCredentialResponse | null>(
    null
  );
  const [isLoading, setIsLoading] = useState<boolean>(false);

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
    navigate("/register-key");
  };

  useEffect(() => {
    (async () => {
      setIsLoading(true);
      const creds = await getCredentials();
      setCredentials(creds);
      setIsLoading(false);
    })();
  }, []);

  return (
    <div className="dashboard-container">
      <h1>Hello, {username}!</h1>
      <div>
        <div className="account-container">
          <h2> Account management </h2>
          <h3> Two-factor authentication </h3>
          {isLoading ? <div>Loading...</div> :
            credentials === null ? null : (
              <div className="credential-container">
                {credentials.credentials.length > 0 ? (
                  <>
                    <h4> Registered keys: </h4>
                    {credentials.credentials.map((cred) => {
                      return <CredentialItem cred={cred} />;
                    })}
                  </>
                ) : (
                  <div> No keys associated with this account. </div>
                )}
              </div>
            )}
          <button
            onClick={handleAddKey}
            className="primary-button credential-btn"
          >
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
