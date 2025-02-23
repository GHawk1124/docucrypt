CREATE TYPE clearance_level AS ENUM ('UNCLASSIFIED', 'CUI', 'SECRET', 'TOPSECRET');

CREATE TABLE IF NOT EXISTS users (
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    group_names VARCHAR(255)[] DEFAULT ARRAY[]::VARCHAR[]
);

CREATE TABLE IF NOT EXISTS groups (
    group_name VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    aes_key VARCHAR(255) NOT NULL,
    tags VARCHAR(255)[] DEFAULT ARRAY[]::VARCHAR[],
    admins VARCHAR(255)[] DEFAULT ARRAY[]::VARCHAR[],
    unclassified_clearance VARCHAR(255)[] DEFAULT ARRAY[]::VARCHAR[],
    cui_clearance VARCHAR(255)[] DEFAULT ARRAY[]::VARCHAR[],
    secret_clearance VARCHAR(255)[] DEFAULT ARRAY[]::VARCHAR[],
    topsecret_clearance VARCHAR(255)[] DEFAULT ARRAY[]::VARCHAR[]
);

-- CREATE TABLE IF NOT EXISTS user_groups (
--     user_id INTEGER REFERENCES users(id),
--     group_id INTEGER REFERENCES groups(id),
--     PRIMARY KEY (user_id, group_id)
-- );
