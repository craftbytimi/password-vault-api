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

## Notes
- AES-256, or Advanced Encryption Standard with a 256-bit key, is one of the most secure encryption algorithms available today. It is a symmetric key encryption standard adopted by the U.S. government and widely used across various industries for securing sensitive data. The strength of AES-256 lies in its large key size, which makes brute-force attacks virtually impractical. With its robust security features and efficiency, AES-256 is the go-to choice for protecting data in transit and at rest.

## Use Cases
- Data-at-Rest Encryption ( organizations can use AES-256 to encrypt sensitive data to protect it from unauthorized access, even if the storage medium is compromised)
- Secure Communication ( it is widely used in vpns and tls/ssl)
- Password Management 
- File Encryption


## Project Roadmap
See the [TODO.md](TODO.md) file for a step-by-step breakdown of tasks.

## License
MIT License
