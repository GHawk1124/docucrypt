import React, { useState, useRef, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";

import { Button } from "./components/ui/button";
import { Input } from "./components/ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "./components/ui/card";
import "./App.css";

type Message = {
  id: number;
  sender: "user" | "bot";
  text: string;
};

function App() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [inputText, setInputText] = useState("");
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Scroll to the bottom of the chat when messages update
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  async function sendMessage() {
    if (!inputText.trim()) return;

    // Add the user's message
    const userMessage: Message = {
      id: Date.now(),
      sender: "user",
      text: inputText,
    };
    setMessages((prev) => [...prev, userMessage]);

    const messageToSend = inputText;
    setInputText("");

    try {
      // Invoke the Tauri command with the user's message.
      const res = await invoke<any>("send_request_command", {
        payload: { prompt: messageToSend },
      });

      // Extract the actual text from the response object
      const botText =
        res && typeof res === "object" && "Response" in res ? res.Response : res;

      const botMessage: Message = {
        id: Date.now() + 1,
        sender: "bot",
        text: botText,
      };
      setMessages((prev) => [...prev, botMessage]);
    } catch (error) {
      console.error("Failed to invoke Tauri command:", error);
      const errorMessage: Message = {
        id: Date.now() + 1,
        sender: "bot",
        text: "Error: Failed to send message.",
      };
      setMessages((prev) => [...prev, errorMessage]);
    }
  }

  // Allow sending the message with the Enter key.
  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter") {
      sendMessage();
    }
  };

  return (
    <div className="min-h-screen bg-gray-100 flex items-center justify-center p-4">
      <Card className="w-full max-w-md shadow-lg">
        <CardHeader>
          <CardTitle className="text-center text-xl font-bold">
            Tauri Chat
          </CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col space-y-2 h-80 overflow-y-auto p-4">
          {messages.map((msg) => (
            <div
              key={msg.id}
              className={`flex ${
                msg.sender === "user" ? "justify-end" : "justify-start"
              }`}
            >
              <div
                className={`rounded-lg p-2 max-w-xs break-words whitespace-pre-wrap ${
                  msg.sender === "user"
                    ? "bg-blue-500 text-white"
                    : "bg-gray-300 text-gray-900"
                }`}
              >
                {msg.text}
              </div>
            </div>
          ))}
          <div ref={messagesEndRef} />
        </CardContent>
        <div className="p-4 border-t border-gray-200 flex space-x-2">
          <Input
            className="flex-grow"
            placeholder="Type your message..."
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
            onKeyDown={handleKeyDown}
          />
          <Button onClick={sendMessage}>Send</Button>
        </div>
      </Card>
    </div>
  );
}

export default App;