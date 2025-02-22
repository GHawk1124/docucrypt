import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { AuthProvider } from "./contexts/AuthContext";
import { ProtectedRoute } from "./components/ProtectedRoute";
import ChatInterface from "./components/ChatInterface";
import DocumentUpload from "./components/DocumentUpload";
import SignInSignUp from "./components/SignInSignUp";
import AccountDetails from "./components/AccountDetails";
import "./assets/styles/App.css";

const queryClient = new QueryClient();

const App = () => {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <BrowserRouter>
          <Routes>
            <Route
              path="/"
              element={<Navigate to="/chat-interface" replace />}
            />
            <Route
              path="/chat-interface"
              element={
                <ProtectedRoute>
                  <ChatInterface />
                </ProtectedRoute>
              }
            />
            <Route
              path="/document-upload"
              element={
                <ProtectedRoute>
                  <DocumentUpload />
                </ProtectedRoute>
              }
            />
            <Route path="/signin-signup" element={<SignInSignUp />} />
            <Route
              path="/account-details"
              element={
                <ProtectedRoute>
                  <AccountDetails />
                </ProtectedRoute>
              }
            />
          </Routes>
        </BrowserRouter>
      </AuthProvider>
    </QueryClientProvider>
  );
};

export default App;
