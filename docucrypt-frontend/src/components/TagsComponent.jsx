import React, { useState } from "react";

const TagsComponent = ({ tags, setTags }) => {
  const [availableTags, setAvailableTags] = useState([
    "Tech",
    "Health",
    "Education",
    "Science",
    "Business",
    "Art",
    "Music",
    "Sports",
    "Travel",
    "Food",
  ]);
  const [newTag, setNewTag] = useState("");

  const handleAddTag = (tag) => {
    if (tag && !tags.includes(tag)) {
      setTags([...tags, tag]);
      setAvailableTags(availableTags.filter((t) => t !== tag));
    }
    setNewTag("");
  };

  const handleRemoveTag = (tag) => {
    setTags(tags.filter((t) => t !== tag));
    setAvailableTags([...availableTags, tag].sort());
  };

  return (
    <div className="p-4 border rounded-lg w-full">
      <label className="block text-sm font-medium mb-2">Group Tags</label>
      <div className="flex flex-wrap gap-2 mb-2">
        {tags.map((tag) => (
          <button
            key={tag}
            className="px-2 py-0.5 text-sm bg-blue-500 text-white rounded-lg flex items-center gap-1"
            onClick={() => handleRemoveTag(tag)}
          >
            {tag} <span className="text-base">×</span>
          </button>
        ))}
      </div>
      <input
        className="w-full p-2 border rounded-lg text-sm focus:outline-none focus:ring-1 focus:ring-blue-500"
        type="text"
        value={newTag}
        onChange={(e) => setNewTag(e.target.value)}
        onKeyDown={(e) => e.key === "Enter" && handleAddTag(newTag)}
        placeholder="Add tags..."
      />
      <div className="flex flex-wrap gap-2 mt-2 p-1">
        {availableTags.map((tag) => (
          <button
            key={tag}
            className="px-2 py-0.5 text-sm border border-gray-300 rounded-lg hover:bg-gray-100"
            onClick={() => handleAddTag(tag)}
          >
            {tag}
          </button>
        ))}
      </div>
    </div>
  );
};

export default TagsComponent;
