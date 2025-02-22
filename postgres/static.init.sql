CREATE TYPE clearance_level AS ENUM ('UNCLASSIFIED', 'CUI', 'SECRET', 'TOPSECRET');

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    clearance clearance_level NOT NULL DEFAULT 'UNCLASSIFIED'
);

CREATE TABLE IF NOT EXISTS groups (
    id SERIAL PRIMARY KEY,
    group_name VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    aes_key VARCHAR(255) NOT NULL,
    tags VARCHAR(255)[] DEFAULT ARRAY[]::VARCHAR[]
);

CREATE TABLE IF NOT EXISTS user_groups (
    user_id INTEGER REFERENCES users(id),
    group_id INTEGER REFERENCES groups(id),
    PRIMARY KEY (user_id, group_id)
);