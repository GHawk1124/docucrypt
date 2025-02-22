import React, { useState, useRef, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../contexts/AuthContext";
import {
  FiUpload,
  FiLogOut,
  FiSend,
  FiMoon,
  FiSun,
  FiTrash2,
} from "react-icons/fi";
import { format } from "date-fns";
import "../assets/styles/App.css";

const ChatInterface = () => {
  const navigate = useNavigate();
  const { logout } = useAuth();
  const [messages, setMessages] = useState([
    {
      id: 1,
      type: "ai",
      content: "Hello! How can I assist you today?",
      timestamp: new Date(),
    },
  ]);
  const [inputMessage, setInputMessage] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [isDarkMode, setIsDarkMode] = useState(false);
  const messagesEndRef = useRef(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const handleSendMessage = async (e) => {
    e.preventDefault();
    if (!inputMessage.trim()) return;

    const userMessage = {
      id: messages.length + 1,
      type: "user",
      content: inputMessage,
      timestamp: new Date(),
    };

    setMessages((prev) => [...prev, userMessage]);
    setInputMessage("");
    setIsLoading(true);

    try {
      // Simulate AI response
      setTimeout(() => {
        const aiMessage = {
          id: messages.length + 2,
          type: "ai",
          content: "This is a simulated AI response to your message.",
          timestamp: new Date(),
        };
        setMessages((prev) => [...prev, aiMessage]);
        setIsLoading(false);
      }, 1500);
    } catch (error) {
      console.error("Error sending message:", error);
      setIsLoading(false);
    }
  };

  const clearChat = () => {
    setMessages([
      {
        id: 1,
        type: "ai",
        content: "Hello! How can I assist you today?",
        timestamp: new Date(),
      },
    ]);
  };

  const handleLogout = () => {
    logout();
    navigate("/signin-signup");
  };

  const handleUploadClick = () => {
    navigate("/document-upload");
  };

  return (
    <div className={`min-h-screen ${isDarkMode ? "dark" : ""}`}>
      <div
        style={{ backgroundColor: "var(--color-background)" }}
        className="flex flex-col h-screen"
      >
        <nav
          style={{ backgroundColor: "var(--color-card)" }}
          className="flex items-center justify-between px-4 py-3 shadow-sm"
        >
          <div className="flex items-center space-x-4">
            <button
              onClick={handleUploadClick}
              className="p-2 rounded-lg hover:opacity-80 transition-colors"
              style={{ backgroundColor: "var(--color-secondary)" }}
            >
              <FiUpload
                style={{ color: "var(--color-accent)" }}
                className="w-5 h-5"
              />
            </button>
          </div>
          <div className="flex items-center space-x-4">
            <button
              onClick={() => setIsDarkMode(!isDarkMode)}
              className="p-2 rounded-lg hover:opacity-80 transition-colors"
              style={{ backgroundColor: "var(--color-secondary)" }}
            >
              {isDarkMode ? (
                <FiSun
                  style={{ color: "var(--color-accent)" }}
                  className="w-5 h-5"
                />
              ) : (
                <FiMoon
                  style={{ color: "var(--color-accent)" }}
                  className="w-5 h-5"
                />
              )}
            </button>
            <button
              onClick={clearChat}
              className="p-2 rounded-lg hover:opacity-80 transition-colors"
              style={{ backgroundColor: "var(--color-secondary)" }}
            >
              <FiTrash2
                style={{ color: "var(--color-accent)" }}
                className="w-5 h-5"
              />
            </button>
            <button
              onClick={handleLogout}
              className="p-2 rounded-lg hover:opacity-80 transition-colors"
              style={{ backgroundColor: "var(--color-secondary)" }}
            >
              <FiLogOut
                style={{ color: "var(--color-accent)" }}
                className="w-5 h-5"
              />
            </button>
          </div>
        </nav>

        <div className="flex-1 overflow-y-auto px-4 py-6 space-y-4">
          {messages.map((message) => (
            <div
              key={message.id}
              className={`flex ${
                message.type === "user" ? "justify-end" : "justify-start"
              }`}
            >
              <div
                style={{
                  backgroundColor:
                    message.type === "user"
                      ? "var(--color-primary)"
                      : "var(--color-secondary)",
                  color:
                    message.type === "user"
                      ? "var(--color-primary-foreground)"
                      : "var(--color-secondary-foreground)",
                }}
                className="max-w-[80%] md:max-w-[60%] rounded-lg p-4"
              >
                <p className="text-body">{message.content}</p>
                <p className="text-xs mt-2 opacity-70">
                  {format(message.timestamp, "HH:mm")}
                </p>
              </div>
            </div>
          ))}
          {isLoading && (
            <div className="flex justify-start">
              <div
                style={{
                  backgroundColor: "var(--color-secondary)",
                  color: "var(--color-secondary-foreground)",
                }}
                className="rounded-lg p-4 max-w-[80%] md:max-w-[60%]"
              >
                <div className="flex space-x-2">
                  <div
                    style={{ backgroundColor: "var(--color-accent)" }}
                    className="w-2 h-2 rounded-full animate-bounce"
                  ></div>
                  <div
                    style={{ backgroundColor: "var(--color-accent)" }}
                    className="w-2 h-2 rounded-full animate-bounce delay-100"
                  ></div>
                  <div
                    style={{ backgroundColor: "var(--color-accent)" }}
                    className="w-2 h-2 rounded-full animate-bounce delay-200"
                  ></div>
                </div>
              </div>
            </div>
          )}
          <div ref={messagesEndRef} />
        </div>

        <form
          onSubmit={handleSendMessage}
          style={{ backgroundColor: "var(--color-card)" }}
          className="p-4 border-t"
        >
          <div className="flex space-x-4">
            <input
              type="text"
              value={inputMessage}
              onChange={(e) => setInputMessage(e.target.value)}
              placeholder="Type your message..."
              style={{
                backgroundColor: "var(--color-background)",
                borderColor: "var(--color-input)",
                "--ring-color": "var(--color-ring)",
              }}
              className="flex-1 px-4 py-2 rounded-lg border focus:outline-none focus:ring-2"
              maxLength={500}
            />
            <button
              type="submit"
              disabled={isLoading || !inputMessage.trim()}
              style={{
                backgroundColor: "var(--color-primary)",
                color: "var(--color-primary-foreground)",
              }}
              className="px-4 py-2 rounded-lg hover:opacity-90 disabled:opacity-50 transition-opacity"
            >
              <FiSend className="w-5 h-5" />
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default ChatInterface;
