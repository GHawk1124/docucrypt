import React, { createContext, useContext, useState } from "react";

const AuthContext = createContext(null);

// export function AuthProvider({ children }) {
//   // Always set isAuthenticated to true for now
//   const [isAuthenticated] = useState(true);

//   const login = () => {
//     // No-op for now
//   };

//   const logout = () => {
//     // No-op for now
//   };

//   return (
//     <AuthContext.Provider value={{ isAuthenticated, login, logout }}>
//       {children}
//     </AuthContext.Provider>
//   );
// }

export function AuthProvider({ children }) {
  const [isAuthenticated, setIsAuthenticated] = useState(() => {
    return localStorage.getItem("auth_token") !== null;
  });
  const [userEmail, setUserEmail] = useState(() => {
    return localStorage.getItem("user_email") || null;
  });

  const login = (token, email) => {
    localStorage.setItem("auth_token", token);
    localStorage.setItem("user_email", email);
    setIsAuthenticated(true);
    setUserEmail(email);
  };

  const logout = () => {
    localStorage.removeItem("auth_token");
    localStorage.removeItem("user_email");
    setIsAuthenticated(false);
    setUserEmail(null);
  };

  return (
    <AuthContext.Provider value={{ isAuthenticated, userEmail, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
