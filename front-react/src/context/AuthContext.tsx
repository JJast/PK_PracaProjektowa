import React, { createContext, useContext, useState, useEffect } from "react";
import { API_BASE_URL } from "../utils/constants";

interface AuthContextType {
  isAuthenticated: boolean;
  username: string | null;
  loading: boolean;
  checkAuth: () => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | null>(null);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
};

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({
  children,
}) => {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [username, setUsername] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const checkAuth = async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/dashboard`, {
        credentials: "include",
      });

      if (res.ok) {
        const data = await res.json();
        setIsAuthenticated(true);
        setUsername(data.username);
      } else {
        setIsAuthenticated(false);
        setUsername(null);
      }
    } catch (err) {
      setIsAuthenticated(false);
      setUsername(null);
    } finally {
      setLoading(false);
    }
  };

  const logout = async () => {
    try {
      await fetch(`${API_BASE_URL}/logout`, {
        credentials: "include",
      });
    } finally {
      setIsAuthenticated(false);
      setUsername(null);
    }
  };

  useEffect(() => {
    checkAuth();
  }, []);

  return (
    <AuthContext.Provider
      value={{ isAuthenticated, username, loading, checkAuth, logout }}
    >
      {children}
    </AuthContext.Provider>
  );
};
