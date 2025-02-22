import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  FiArrowLeft,
  FiLogOut,
  FiUsers,
  FiPlus,
  FiCheck,
  FiX,
} from "react-icons/fi";
import { useAuth } from "../contexts/AuthContext";

const AccountDetails = () => {
  const navigate = useNavigate();
  const { logout, isAuthenticated, userEmail } = useAuth();
  const [groupCode, setGroupCode] = useState("");
  const [groups] = useState(["Hackalytics", "MLH"]); // Sample data
  const securityClearance = "BASIC"; // Sample data
  const isAdmin = true; // Sample data
  const [joinRequests, setJoinRequests] = useState([
    { id: 1, user: "Garrett", group: "Hackalytics", securityLevel: "BASIC" },
    { id: 2, user: "Ivan", group: "MLH", securityLevel: "BASIC" },
  ]); // Sample data
  const adminGroups = ["Hackalytics", "MLH"]; // Groups the user is admin for
  const [requestStatus, setRequestStatus] = useState(""); // State to manage request status message
  const securityLevels = ["BASIC", "SECOND", "TOP SECRET"]; // Security clearance options

  // State for creating a new group
  const [newGroupName, setNewGroupName] = useState("");
  const [newGroupPassword, setNewGroupPassword] = useState("");
  const [newGroupTags, setNewGroupTags] = useState([]);
  const [availableTags, setAvailableTags] = useState([
    "Tech",
    "Health",
    "Education",
  ]); // Sample tags

  useEffect(() => {
    const auth_token = localStorage.getItem("auth_token");
    console.log("Auth Status:", {
      isAuthenticated,
      auth_token,
      userEmail,
      timestamp: new Date().toISOString(),
    });
  }, [isAuthenticated, userEmail]);

  const handleLogout = () => {
    logout();
    navigate("/signin-signup");
  };

  const handleJoinGroup = (e) => {
    e.preventDefault();
    console.log("Attempting to join group with code:", groupCode);

    // Log the selected security clearances for all join requests
    joinRequests.forEach((request) => {
      console.log(
        `User: ${request.user}, Security Level: ${request.securityLevel}`
      );
    });

    setRequestStatus("Request to join submitted!"); // Set request status message
    setGroupCode("");

    // Optionally, you can clear the message after a few seconds
    setTimeout(() => {
      setRequestStatus("");
    }, 3000);
  };

  const handleJoinRequest = (requestId, action) => {
    console.log(`${action} join request:`, requestId);
    if (action === "approve") {
      setJoinRequests((prevRequests) =>
        prevRequests.filter((request) => request.id !== requestId)
      );
    } else if (action === "deny") {
      setJoinRequests((prevRequests) =>
        prevRequests.filter((request) => request.id !== requestId)
      );
    }
  };

  const handleSecurityLevelChange = (requestId, newLevel) => {
    setJoinRequests((prevRequests) =>
      prevRequests.map((request) =>
        request.id === requestId
          ? { ...request, securityLevel: newLevel }
          : request
      )
    );
    console.log(`Selected security level for request ${requestId}:`, newLevel);
  };

  const handleCreateGroup = (e) => {
    e.preventDefault();
    console.log(
      "Creating group:",
      newGroupName,
      "with password:",
      newGroupPassword,
      "and tags:",
      newGroupTags
    );
    // Reset form fields
    setNewGroupName("");
    setNewGroupPassword("");
    setNewGroupTags([]);
    // Optionally, you can add logic to actually create the group
  };

  return (
    <div
      className="min-h-screen"
      style={{ backgroundColor: "var(--color-background)" }}
    >
      <nav
        style={{ backgroundColor: "var(--color-card)" }}
        className="flex items-center justify-between px-4 py-3 shadow-sm"
      >
        <button
          onClick={() => navigate(-1)}
          className="p-2 rounded-lg hover:opacity-80 transition-colors cursor-pointer"
          style={{ backgroundColor: "var(--color-secondary)" }}
        >
          <FiArrowLeft
            style={{ color: "var(--color-accent)" }}
            className="w-5 h-5"
          />
        </button>
        <button
          onClick={handleLogout}
          className="p-2 rounded-lg hover:opacity-80 transition-colors cursor-pointer"
          style={{ backgroundColor: "var(--color-secondary)" }}
        >
          <FiLogOut
            style={{ color: "var(--color-accent)" }}
            className="w-5 h-5"
          />
        </button>
      </nav>

      <div className="container mx-auto px-4 py-8 max-w-2xl">
        <h1
          className="text-2xl font-bold mb-8"
          style={{ color: "var(--color-foreground)" }}
        >
          Account Details
        </h1>

        <div className="space-y-6">
          {/* User Info Section */}
          <div
            className="p-6 rounded-lg"
            style={{ backgroundColor: "var(--color-card)" }}
          >
            <h2
              className="text-lg font-semibold mb-4"
              style={{ color: "var(--color-foreground)" }}
            >
              User Information
            </h2>
            <div className="space-y-2">
              <p style={{ color: "var(--color-foreground)" }}>
                <span className="font-medium">Email:</span> {userEmail}
              </p>
              <p style={{ color: "var(--color-foreground)" }}>
                <span className="font-medium">Security Clearance:</span>{" "}
                <span
                  className="px-2 py-1 rounded text-sm"
                  style={{ backgroundColor: "var(--color-secondary)" }}
                >
                  {securityClearance}
                </span>
              </p>
              <p style={{ color: "var(--color-foreground)" }}>
                <span className="font-medium">Admin Groups:</span>
                <ul className="list-disc list-inside">
                  {adminGroups.map((group, index) => (
                    <li
                      key={index}
                      style={{ color: "var(--color-foreground)" }}
                    >
                      {group}
                    </li>
                  ))}
                </ul>
              </p>
            </div>
          </div>

          {/* Create Group Section */}
          {isAdmin && (
            <div
              className="p-6 rounded-lg"
              style={{ backgroundColor: "var(--color-card)" }}
            >
              <h2
                className="text-lg font-semibold mb-4"
                style={{ color: "var(--color-foreground)" }}
              >
                Create Group
              </h2>
              <form onSubmit={handleCreateGroup} className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700">
                    Group Name
                  </label>
                  <input
                    type="text"
                    value={newGroupName}
                    onChange={(e) => setNewGroupName(e.target.value)}
                    required
                    className="mt-1 block w-full p-2 border border-gray-300 rounded-md"
                    placeholder="Enter group name"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">
                    Password
                  </label>
                  <input
                    type="password"
                    value={newGroupPassword}
                    onChange={(e) => setNewGroupPassword(e.target.value)}
                    required
                    className="mt-1 block w-full p-2 border border-gray-300 rounded-md"
                    placeholder="Enter password"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">
                    Tags
                  </label>
                  <select
                    multiple
                    value={newGroupTags}
                    onChange={(e) => {
                      const options = e.target.options;
                      const selectedTags = [];
                      for (let i = 0; i < options.length; i++) {
                        if (options[i].selected) {
                          selectedTags.push(options[i].value);
                        }
                      }
                      setNewGroupTags(selectedTags);
                    }}
                    className="mt-1 block w-full p-2 border border-gray-300 rounded-md"
                  >
                    {availableTags.map((tag, index) => (
                      <option key={index} value={tag}>
                        {tag}
                      </option>
                    ))}
                    <option value="custom">Add custom tag...</option>
                  </select>
                </div>
                <button
                  type="submit"
                  className="px-4 py-2 rounded bg-blue-600 text-white hover:bg-blue-700"
                >
                  Create Group
                </button>
              </form>
            </div>
          )}

          {/* Groups Section */}
          <div
            className="p-6 rounded-lg"
            style={{ backgroundColor: "var(--color-card)" }}
          >
            <div className="flex items-center justify-between mb-4">
              <h2
                className="text-lg font-semibold"
                style={{ color: "var(--color-foreground)" }}
              >
                Groups
              </h2>
              <FiUsers
                className="w-5 h-5"
                style={{ color: "var(--color-accent)" }}
              />
            </div>

            {/* Current Groups */}
            <div className="mb-6">
              <div className="space-y-2">
                {groups.map((group, index) => (
                  <div
                    key={index}
                    className="flex items-center p-3 rounded"
                    style={{ backgroundColor: "var(--color-secondary)" }}
                  >
                    <span style={{ color: "var(--color-foreground)" }}>
                      {group}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* Join Group Form */}
            <form onSubmit={handleJoinGroup} className="space-y-3">
              <div className="flex gap-2">
                <input
                  type="text"
                  value={groupCode}
                  onChange={(e) => setGroupCode(e.target.value)}
                  placeholder="Enter group code"
                  className="flex-1 px-4 py-2 rounded border"
                  style={{
                    backgroundColor: "var(--color-background)",
                    borderColor: "var(--color-border)",
                    color: "var(--color-foreground)",
                  }}
                  required
                />
                <button
                  type="submit"
                  className="px-4 py-2 rounded flex items-center gap-2 transition-colors hover:opacity-90"
                  style={{
                    backgroundColor: "var(--color-primary)",
                    color: "var(--color-primary-foreground)",
                  }}
                >
                  <FiPlus className="w-4 h-4" />
                  Request to Join
                </button>
              </div>
              {requestStatus && (
                <p className="text-green-500">{requestStatus}</p> // Show request status message
              )}
            </form>
          </div>

          {/* Admin Section */}
          {isAdmin && (
            <div
              className="p-6 rounded-lg"
              style={{ backgroundColor: "var(--color-card)" }}
            >
              <div className="flex items-center justify-between mb-4">
                <h2
                  className="text-lg font-semibold"
                  style={{ color: "var(--color-foreground)" }}
                >
                  Pending Join Requests
                </h2>
                <FiUsers
                  className="w-5 h-5"
                  style={{ color: "var(--color-accent)" }}
                />
              </div>

              {joinRequests.length > 0 ? (
                <div className="space-y-3">
                  {joinRequests.map((request) => (
                    <div
                      key={request.id}
                      className="flex items-center justify-between p-4 rounded"
                      style={{ backgroundColor: "var(--color-secondary)" }}
                    >
                      <div style={{ color: "var(--color-foreground)" }}>
                        <span className="font-medium">{request.user}</span>
                        <span className="mx-2">→</span>
                        <span>{request.group}</span>
                      </div>
                      <div className="flex gap-2">
                        {/* Security Level Dropdown */}
                        <select
                          value={request.securityLevel}
                          onChange={(e) =>
                            handleSecurityLevelChange(
                              request.id,
                              e.target.value
                            )
                          }
                          className="p-2 rounded border border-gray-300 bg-white text-gray-700 focus:outline-none focus:ring focus:ring-blue-500"
                        >
                          {securityLevels.map((level, index) => (
                            <option key={index} value={level}>
                              {level}
                            </option>
                          ))}
                        </select>
                        <button
                          onClick={() =>
                            handleJoinRequest(request.id, "approve")
                          }
                          className="p-2 rounded transition-colors hover:opacity-90"
                          style={{ backgroundColor: "var(--color-primary)" }}
                        >
                          <FiCheck className="w-4 h-4 text-white" />
                        </button>
                        <button
                          onClick={() => handleJoinRequest(request.id, "deny")}
                          className="p-2 rounded transition-colors hover:opacity-90"
                          style={{
                            backgroundColor: "var(--color-destructive)",
                          }}
                        >
                          <FiX className="w-4 h-4 text-white" />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <p
                  className="text-sm italic"
                  style={{ color: "var(--color-foreground)" }}
                >
                  No pending join requests
                </p>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default AccountDetails;
