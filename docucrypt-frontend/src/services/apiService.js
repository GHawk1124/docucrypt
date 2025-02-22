import axios from "axios";

const API_URL = "http://localhost:3000"; // Replace with your actual backend URL

// Sign Up
export const signUp = async (username, password) => {
  try {
    const response = await axios.post(
      `${API_URL}/register`,
      {
        username,
        password,
      },
      {
        headers: {
          "Content-Type": "application/json",
        },
      }
    );
    return response.data;
  } catch (error) {
    throw error;
  }
};

// Log In
export const userLogin = async (username, password) => {
  try {
    const response = await axios.post(
      `${API_URL}/login`,
      {
        username,
        password,
      },
      {
        headers: {
          "Content-Type": "application/json",
        },
      }
    );
    return response.data;
  } catch (error) {
    throw error;
  }
};

// Query
export const query = async (prompt, model, token, timeoutSecs) => {
  try {
    const response = await axios.post(
      `${API_URL}/query`,
      {
        prompt,
        model,
        timeout_secs: timeoutSecs,
      },
      {
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
      }
    );
    return response.data;
  } catch (error) {
    throw error;
  }
};

// Update User Clearance
export const updateUserClearance = async (userId, newClearance, token) => {
  try {
    const response = await axios.put(
      `${API_URL}/users/clearance`,
      {
        user_id: userId,
        new_clearance: newClearance,
      },
      {
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
      }
    );
    return response.data;
  } catch (error) {
    throw error;
  }
};

// Add User to Group
export const addUserToGroup = async (userId, groupId, token) => {
  try {
    const response = await axios.post(
      `${API_URL}/groups/users`,
      {
        user_id: userId,
        group_id: groupId,
      },
      {
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
      }
    );
    return response.data;
  } catch (error) {
    throw error;
  }
};

// Add Admin to Group
export const addAdminToGroup = async (userId, groupId, token) => {
  try {
    const response = await axios.post(
      `${API_URL}/groups/admins`,
      {
        user_id: userId,
        group_id: groupId,
      },
      {
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
      }
    );
    return response.data;
  } catch (error) {
    throw error;
  }
};

// Create Group
export const createGroup = async (groupData, token) => {
  try {
    const response = await axios.post(`${API_URL}/groups`, groupData, {
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
    });
    return response.data;
  } catch (error) {
    throw error;
  }
};

// Join Group
export const joinGroup = async (groupName, password, token) => {
  try {
    const response = await axios.post(
      `${API_URL}/groups/users/join`,
      {
        group_name: groupName,
        password,
      },
      {
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
      }
    );
    return response.data;
  } catch (error) {
    throw error;
  }
};

// Get Group Details
export const getGroupDetails = async (groupId, token) => {
  // Mock data
  const mockMembers = {
    1: [{ id: 1, username: "John Doe", clearance_level: "BASIC" }],
    2: [{ id: 2, username: "Jane Doe", clearance_level: "SECOND" }],
  };
  return {
    id: groupId,
    members: mockMembers[groupId] || [],
  };
};

// Delete Group
export const deleteGroup = async (groupId, token) => {
  try {
    const response = await axios.delete(`${API_URL}/groups/${groupId}`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });
    return response.data;
  } catch (error) {
    throw error;
  }
};

// For testing - replace with actual API call later
export const getAdminGroups = async (token) => {
  // Mock data
  return [
    { id: 1, name: "Hacklytics" },
    { id: 2, name: "MLH" },
  ];
};
