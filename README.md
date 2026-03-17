# Password Vault API

## Overview
A secure API for storing username and password pairs for websites. All credentials are encrypted at rest using AES-256. The master password is used to derive the encryption key, ensuring only the owner can decrypt their data. The API supports basic CRUD operations and search functionality.

## Features
- AES-256 encryption for all stored credentials
- Key derivation from master password
- Envelope encryption pattern for secure storage
- CRUD operations: Create, Read, Update, Delete
- Search functionality for credentials
- User authentication with JWT
- PostgreSQL database with GORM ORM
- Built with Gin web framework

## Tech Stack
- Gin (Go web framework)
- PostgreSQL
- GORM (ORM for Go)
- Go crypto/aes package

## API Endpoints
- `POST /register` — Register a new user
- `POST /login` — Authenticate user and return token
- `POST /vault` — Add a new credential (encrypted)
- `GET /vault` — List all credentials
- `GET /vault/search?q=site` — Search credentials by site
- `PUT /vault/:id` — Update a credential
- `DELETE /vault/:id` — Delete a credential

## Security
- All credentials encrypted with AES-256
- Encryption key derived from master password (PBKDF2 or similar)
- Envelope encryption for secure key management
- Only the owner can decrypt their credentials

## Getting Started

1. Clone the repository
2. Install dependencies:
   ```bash
   go mod tidy
   ```
3. Set up PostgreSQL and configure environment variables
4. Run the server:
   ```bash
   go run cmd/server/main.go
   ```
5. Use the API via Postman or curl

## Environment Variables

- `DB_HOST`
- `DB_PORT`
- `DB_USER`
- `DB_PASSWORD`
- `DB_NAME`
- `JWT_SECRET`

## Project Roadmap
See the [TODO.md](TODO.md) file for a step-by-step breakdown of tasks.

## License
MIT License
