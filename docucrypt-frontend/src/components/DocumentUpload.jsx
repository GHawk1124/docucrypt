import { useState, useRef } from "react";
import {
  FiUpload,
  FiX,
  FiFile,
  FiCheck,
  FiAlertCircle,
  FiMessageSquare,
  FiLogOut,
  FiMoon,
  FiSun,
  FiUser,
} from "react-icons/fi";
import "../assets/styles/App.css";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../contexts/AuthContext";

const DocumentUpload = () => {
  const [files, setFiles] = useState([]);
  const [isDragging, setIsDragging] = useState(false);
  const [uploadProgress, setUploadProgress] = useState({});
  const [errors, setErrors] = useState({});
  const [previews, setPreviews] = useState({});
  const [uploading, setUploading] = useState(false);
  const fileInputRef = useRef(null);
  const navigate = useNavigate();
  const { logout } = useAuth();
  const [isDarkMode, setIsDarkMode] = useState(false);

  const MAX_FILE_SIZE = 5 * 1024 * 1024;

  const handleDragEnter = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.currentTarget.contains(e.relatedTarget)) return;
    setIsDragging(false);
  };

  const validateFile = (file) => {
    if (!file.name.endsWith(".txt")) {
      return "Only .txt files are allowed";
    }
    if (file.size > MAX_FILE_SIZE) {
      return "File size exceeds 5MB limit";
    }
    return null;
  };

  const handleFileSelect = async (selectedFiles) => {
    const filesArray = Array.from(selectedFiles);
    const newFiles = [];
    const newErrors = {};
    const newPreviews = {};

    for (const file of filesArray) {
      const error = validateFile(file);
      if (error) {
        newErrors[file.name] = error;
      } else {
        newFiles.push(file);
        const reader = new FileReader();
        reader.onload = (e) => {
          setPreviews((prev) => ({
            ...prev,
            [file.name]: e.target.result,
          }));
        };
        reader.readAsText(file);
      }
    }

    setFiles((prev) => [...prev, ...newFiles]);
    setErrors((prev) => ({ ...prev, ...newErrors }));
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);

    if (e.dataTransfer.files) {
      const droppedFiles = Array.from(e.dataTransfer.files);
      handleFileSelect(droppedFiles);
    }
  };

  const simulateUpload = () => {
    setUploading(true);
    const newProgress = {};
    files.forEach((file) => {
      newProgress[file.name] = 0;
    });
    setUploadProgress(newProgress);

    files.forEach((file) => {
      const interval = setInterval(() => {
        setUploadProgress((prev) => {
          const currentProgress = prev[file.name];
          if (currentProgress >= 100) {
            clearInterval(interval);
            return prev;
          }
          return {
            ...prev,
            [file.name]: currentProgress + 10,
          };
        });
      }, 300);
    });

    // Reset uploading state when all files are done
    const checkCompletion = setInterval(() => {
      setUploadProgress((prev) => {
        if (Object.values(prev).every((progress) => progress >= 100)) {
          clearInterval(checkCompletion);
          setUploading(false);
          return prev;
        }
        return prev;
      });
    }, 100);
  };

  const resetUpload = () => {
    setFiles([]);
    setPreviews({});
    setErrors({});
    setUploadProgress({});
    setUploading(false);
    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  };

  const removeFile = (fileName) => {
    setFiles((prev) => prev.filter((file) => file.name !== fileName));
    setPreviews((prev) => {
      const newPreviews = { ...prev };
      delete newPreviews[fileName];
      return newPreviews;
    });
    setErrors((prev) => {
      const newErrors = { ...prev };
      delete newErrors[fileName];
      return newErrors;
    });
    setUploadProgress((prev) => {
      const newProgress = { ...prev };
      delete newProgress[fileName];
      return newProgress;
    });
  };

  const handleLogout = () => {
    logout();
    navigate("/signin-signup");
  };

  const handleChatClick = () => {
    navigate("/chat-interface");
  };

  const handleAccountClick = () => {
    navigate("/account-details");
  };

  const handleSendFiles = () => {
    // print out the files uploaded and their contents
    files.forEach((file) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        console.log("File:", file.name);
        console.log("Contents:", e.target.result);
      };
      reader.readAsText(file);
    });
    resetUpload();
    // navigate("/chat-interface");
  };

  const handleSectionClick = () => {
    fileInputRef.current?.click();
  };

  return (
    <div className={`min-h-screen ${isDarkMode ? "dark" : ""}`}>
      <div
        style={{ backgroundColor: "var(--color-background)" }}
        className="flex flex-col min-h-screen"
      >
        <nav
          style={{ backgroundColor: "var(--color-card)" }}
          className="flex items-center justify-between px-4 py-3 shadow-sm"
        >
          <div className="flex items-center space-x-4">
            <button
              onClick={handleChatClick}
              className="p-2 rounded-lg hover:opacity-80 transition-colors cursor-pointer"
              style={{ backgroundColor: "var(--color-secondary)" }}
            >
              <FiMessageSquare
                style={{ color: "var(--color-accent)" }}
                className="w-5 h-5"
              />
            </button>
          </div>
          <div className="flex items-center space-x-4">
            <button
              onClick={handleAccountClick}
              className="p-2 rounded-lg hover:opacity-80 transition-colors cursor-pointer"
              style={{ backgroundColor: "var(--color-secondary)" }}
            >
              <FiUser
                style={{ color: "var(--color-accent)" }}
                className="w-5 h-5"
              />
            </button>
            <button
              onClick={() => setIsDarkMode(!isDarkMode)}
              className="p-2 rounded-lg hover:opacity-80 transition-colors cursor-pointer"
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
              onClick={handleLogout}
              className="p-2 rounded-lg hover:opacity-80 transition-colors cursor-pointer"
              style={{ backgroundColor: "var(--color-secondary)" }}
            >
              <FiLogOut
                style={{ color: "var(--color-accent)" }}
                className="w-5 h-5"
              />
            </button>
          </div>
        </nav>

        <div className="flex-1 p-6">
          <div className="max-w-2xl mx-auto">
            <div
              onClick={handleSectionClick}
              className={`border-2 border-dashed rounded-lg p-8 transition-all duration-200 cursor-pointer hover:border-[var(--color-primary)] hover:bg-[var(--color-primary)]/5 ${
                Object.keys(errors).length > 0
                  ? "border-[var(--color-destructive)]"
                  : "border-[var(--color-border)]"
              }`}
            >
              <div className="flex flex-col items-center justify-center space-y-4">
                <FiUpload className="w-12 h-12 text-[var(--color-accent)]" />
                <div className="text-center">
                  <p className="text-lg font-semibold">
                    Click to select .txt files
                  </p>
                  <p className="text-sm text-[var(--color-accent)]">
                    You can select multiple files
                  </p>
                </div>
                <input
                  type="file"
                  ref={fileInputRef}
                  onChange={(e) => handleFileSelect(e.target.files)}
                  className="hidden"
                  accept=".txt"
                  multiple
                />
              </div>
            </div>

            {files.length > 0 && (
              <div className="mt-4 space-y-4">
                {files.map((file) => (
                  <div
                    key={file.name}
                    className="bg-[var(--color-card)] p-4 rounded-lg"
                  >
                    <div className="flex items-center justify-between mb-4">
                      <div className="flex items-center space-x-3">
                        <FiFile className="w-8 h-8 text-[var(--color-primary)]" />
                        <span className="font-medium">{file.name}</span>
                      </div>
                      <button
                        onClick={() => removeFile(file.name)}
                        className="p-2 hover:bg-[var(--color-secondary)] rounded-full transition-colors cursor-pointer"
                        aria-label="Remove file"
                      >
                        <FiX className="w-5 h-5 text-[var(--color-accent)]" />
                      </button>
                    </div>

                    {previews[file.name] && (
                      <div className="mb-4 p-4 bg-[var(--color-secondary)] rounded-md"></div>
                    )}

                    {uploadProgress[file.name] > 0 && (
                      <div className="w-full bg-[var(--color-secondary)] rounded-full h-2 mb-4">
                        <div
                          className="bg-[var(--color-primary)] h-2 rounded-full transition-all duration-300"
                          style={{ width: `${uploadProgress[file.name]}%` }}
                        />
                      </div>
                    )}
                  </div>
                ))}

                <div className="flex justify-end space-x-3">
                  <button
                    onClick={resetUpload}
                    className="px-4 py-2 border border-[var(--color-border)] rounded-md hover:bg-[var(--color-secondary)] transition-colors cursor-pointer disabled:cursor-not-allowed"
                    disabled={uploading}
                  >
                    Cancel
                  </button>
                  {Object.values(uploadProgress).every(
                    (progress) => progress >= 100
                  ) ? (
                    <button
                      onClick={handleSendFiles}
                      className="px-4 py-2 bg-[var(--color-accent)] text-white rounded-md hover:opacity-90 focus:outline-none focus:ring-2 focus:ring-[var(--color-accent)] focus:ring-offset-2 transition-colors cursor-pointer"
                    >
                      Upload to server
                    </button>
                  ) : (
                    <button
                      onClick={simulateUpload}
                      disabled={uploading || files.length === 0}
                      className="px-4 py-2 bg-[var(--color-primary)] text-[var(--color-primary-foreground)] rounded-md hover:bg-[var(--color-primary)]/90 focus:outline-none focus:ring-2 focus:ring-[var(--color-primary)] focus:ring-offset-2 transition-colors disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
                    >
                      {uploading ? "Uploading..." : "Upload Files"}
                    </button>
                  )}
                </div>
              </div>
            )}

            {Object.entries(errors).map(([fileName, error]) => (
              <div
                key={fileName}
                className="mt-4 p-4 bg-[var(--color-destructive)]/10 text-[var(--color-destructive)] rounded-md flex items-center"
              >
                <FiAlertCircle className="w-5 h-5 mr-2" />
                {fileName}: {error}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default DocumentUpload;
