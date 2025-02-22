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
import {
  joinGroup,
  updateUserClearance,
  addUserToGroup,
  createGroup,
} from "../services/apiService";
import TagsComponent from "./TagsComponent";

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
  const [selectedTags, setSelectedTags] = useState([]);

  const [groupName, setGroupName] = useState("");
  const [groupPassword, setGroupPassword] = useState("");

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

  const handleJoinGroup = async (e) => {
    e.preventDefault();
    console.log("Attempting to join group:", groupName);

    try {
      await joinGroup(groupName, groupPassword, token);

      setRequestStatus("Request to join submitted!"); // Set success message
      setGroupName("");
      setGroupPassword("");

      // Clear the message after a few seconds
      setTimeout(() => {
        setRequestStatus("");
      }, 3000);
    } catch (error) {
      console.error("Error joining group:", error);
      setRequestStatus(
        "Failed to join group: " +
          (error.response?.data?.message || error.message)
      );

      // Clear error message after a few seconds
      setTimeout(() => {
        setRequestStatus("");
      }, 3000);
    }
  };

  const handleJoinRequest = async (requestId, action) => {
    console.log(`${action} join request:`, requestId);

    if (action === "approve") {
      try {
        const request = joinRequests.find((req) => req.id === requestId);

        // Update user's security clearance
        await updateUserClearance(request.user, request.securityLevel, token);

        // Add user to the group using the group name
        await addUserToGroup(request.user, request.group, token);

        // Remove request from the list
        setJoinRequests((prevRequests) =>
          prevRequests.filter((request) => request.id !== requestId)
        );

        // Optionally show success message
        console.log("Successfully approved user join request");
      } catch (error) {
        console.error("Error processing join request:", error);
        // Optionally show error message to user
      }
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

  const handleCreateGroup = async (e) => {
    e.preventDefault();
    console.log(
      "Creating group:",
      newGroupName,
      "with password:",
      newGroupPassword,
      "and tags:",
      selectedTags
    );

    try {
      const groupData = {
        group_name: newGroupName,
        password: newGroupPassword,
        tags: selectedTags,
      };

      await createGroup(groupData, token);

      // Reset form fields
      setNewGroupName("");
      setNewGroupPassword("");
      setSelectedTags([]);

      // Optionally show success message
      setRequestStatus("Group created successfully!");
      setTimeout(() => {
        setRequestStatus("");
      }, 3000);
    } catch (error) {
      console.error("Error creating group:", error);
      setRequestStatus(
        "Failed to create group: " +
          (error.response?.data?.message || error.message)
      );
      setTimeout(() => {
        setRequestStatus("");
      }, 3000);
    }
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
                <TagsComponent tags={selectedTags} setTags={setSelectedTags} />
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
                  value={groupName}
                  onChange={(e) => setGroupName(e.target.value)}
                  placeholder="Enter group name"
                  className="flex-1 px-4 py-2 rounded border"
                  style={{
                    backgroundColor: "var(--color-background)",
                    borderColor: "var(--color-border)",
                    color: "var(--color-foreground)",
                  }}
                  required
                />
                <input
                  type="password"
                  value={groupPassword}
                  onChange={(e) => setGroupPassword(e.target.value)}
                  placeholder="Enter password"
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
                <p
                  className={
                    requestStatus.includes("Failed")
                      ? "text-red-500"
                      : "text-green-500"
                  }
                >
                  {requestStatus}
                </p>
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
