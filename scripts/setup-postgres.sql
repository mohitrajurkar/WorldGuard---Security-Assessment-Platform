-- ============================================================
-- SIH26163 Security Platform - PostgreSQL Database Initialization
-- ============================================================

-- Create the database if it doesn't already exist
CREATE DATABASE wm_security;

-- Optional: Grant full privileges to the postgres user
GRANT ALL PRIVILEGES ON DATABASE wm_security TO postgres;
