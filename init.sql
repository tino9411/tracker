CREATE DATABASE user_db;

\\c user_db

-- Create User Table
CREATE TABLE user (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  username VARCHAR(50) NOT NULL UNIQUE,
  email VARCHAR(100) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  first_name VARCHAR(50),
  last_name VARCHAR(50),
  date_created TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_login_time TIMESTAMPTZ

);
