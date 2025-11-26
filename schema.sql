-- CREATE DATABASE IF NOT EXISTS database;

CREATE TABLE IF NOT EXISTS Users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    hashed_password TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    display_name TEXT
);

CREATE TABLE IF NOT EXISTS ProgressLogs(
    -- id, user_id, date, title, details, image_path nullable
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    date TEXT NOT NULL,
    title TEXT NOT NULL,
    details TEXT NOT NULL,
    image_path TEXT

);

CREATE TABLE IF NOT EXISTS Quizzes(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS Questions(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    quiz_id INTEGER NOT NULL,
    question TEXT NOT NULL,
    answer TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS FlashcardSet(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS Flashcards(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    set_id INTEGER NOT NULL,
    front TEXT NOT NULL,
    back TEXT NOT NULL
);

ALTER TABLE Users
    ADD COLUMN score INTEGER;


/*
ALTER TABLE Questions
    ADD choice1 TEXT NOT NULL;
ALTER TABLE Questions
    ADD choice2 TEXT NOT NULL;
ALTER TABLE Questions
    ADD choice3 TEXT NOT NULL;
ALTER TABLE Questions
    ADD choice4 TEXT NOT NULL;
ALTER TABLE Questions
    ADD correct_index TEXT NOT NULL;

ALTER TABLE Questions
    DROP COLUMN answer;



--- sqlite3 database.db ".read schema.sql"

 */