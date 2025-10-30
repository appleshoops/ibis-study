-- CREATE DATABASE IF NOT EXISTS database;

CREATE TABLE IF NOT EXISTS Users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    hashed_password TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    display_name TEXT
);


--- sqlite3 database.db "read schema.sql"