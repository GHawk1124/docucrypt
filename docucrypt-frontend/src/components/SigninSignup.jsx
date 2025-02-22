import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../contexts/AuthContext";
import { FiMail, FiLock, FiUser } from "react-icons/fi";

const SignInSignUp = () => {
  const [isSignIn, setIsSignIn] = useState(true);
  const [formData, setFormData] = useState({
    email: "",
    password: "",
    name: "",
  });
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    // Add your authentication logic here
    // For now, we'll just simulate a successful login
    login("dummy_token");
    navigate("/chat-interface");
  };

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData((prev) => ({
      ...prev,
      [name]: value,
    }));
  };

  return (
    <div
      className="min-h-screen flex items-center justify-center"
      style={{ backgroundColor: "var(--color-background)" }}
    >
      <div
        className="w-full max-w-md p-8 rounded-xl shadow-lg"
        style={{ backgroundColor: "var(--color-card)" }}
      >
        <h2
          className="text-2xl font-bold text-center mb-6"
          style={{ color: "var(--color-foreground)" }}
        >
          {isSignIn ? "Welcome Back" : "Create Account"}
        </h2>
        <form onSubmit={handleSubmit} className="space-y-4">
          {!isSignIn && (
            <div className="relative">
              <FiUser className="absolute left-3 top-1/2 transform -translate-y-1/2 text-accent" />
              <input
                type="text"
                name="name"
                value={formData.name}
                onChange={handleInputChange}
                placeholder="Full Name"
                className="w-full pl-10 pr-4 py-2 rounded border"
                style={{
                  backgroundColor: "var(--color-background)",
                  borderColor: "var(--color-border)",
                  color: "var(--color-foreground)",
                }}
                required
              />
            </div>
          )}
          <div className="relative">
            <FiMail className="absolute left-3 top-1/2 transform -translate-y-1/2 text-accent" />
            <input
              type="email"
              name="email"
              value={formData.email}
              onChange={handleInputChange}
              placeholder="Email Address"
              className="w-full pl-10 pr-4 py-2 rounded border"
              style={{
                backgroundColor: "var(--color-background)",
                borderColor: "var(--color-border)",
                color: "var(--color-foreground)",
              }}
              required
            />
          </div>
          <div className="relative">
            <FiLock className="absolute left-3 top-1/2 transform -translate-y-1/2 text-accent" />
            <input
              type="password"
              name="password"
              value={formData.password}
              onChange={handleInputChange}
              placeholder="Password"
              className="w-full pl-10 pr-4 py-2 rounded border"
              style={{
                backgroundColor: "var(--color-background)",
                borderColor: "var(--color-border)",
                color: "var(--color-foreground)",
              }}
              required
            />
          </div>
          <button
            type="submit"
            className="w-full py-2 px-4 rounded transition-colors"
            style={{
              backgroundColor: "var(--color-primary)",
              color: "var(--color-primary-foreground)",
            }}
          >
            {isSignIn ? "Sign In" : "Sign Up"}
          </button>
        </form>
        <div className="mt-4 text-center">
          <button
            onClick={() => setIsSignIn(!isSignIn)}
            className="text-sm hover:underline"
            style={{ color: "var(--color-accent)" }}
          >
            {isSignIn
              ? "Don't have an account? Sign Up"
              : "Already have an account? Sign In"}
          </button>
        </div>
      </div>
    </div>
  );
};

export default SignInSignUp;
