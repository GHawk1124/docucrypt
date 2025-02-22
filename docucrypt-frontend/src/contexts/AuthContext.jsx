import React, { createContext, useContext, useState } from "react";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  // Always set isAuthenticated to true for now
  const [isAuthenticated] = useState(true);

  const login = () => {
    // No-op for now
  };

  const logout = () => {
    // No-op for now
  };

  return (
    <AuthContext.Provider value={{ isAuthenticated, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

// export function AuthProvider({ children }) {
//   const [isAuthenticated, setIsAuthenticated] = useState(() => {
//     return localStorage.getItem("auth_token") !== null;
//   });

//   const login = (token) => {
//     localStorage.setItem("auth_token", token);
//     setIsAuthenticated(true);
//   };

//   const logout = () => {
//     localStorage.removeItem("auth_token");
//     setIsAuthenticated(false);
//   };

//   return (
//     <AuthContext.Provider value={{ isAuthenticated, login, logout }}>
//       {children}
//     </AuthContext.Provider>
//   );
// }

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
