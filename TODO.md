
# TODO List: Password Vault API (Step-by-Step)

1. Initialize Go module
2. Set up Gin web framework
3. Set up GORM ORM
4. Configure PostgreSQL connection
5. Implement user registration (with master password)
6. Implement user login and JWT token generation
7. Implement AES-256 encryption for credentials
8. Derive encryption key from master password
9. Use envelope encryption for key management
10. Create credential (encrypt before storing)
11. Read credential (decrypt after fetching)
12. Update credential (re-encrypt if changed)
13. Delete credential
14. Implement search endpoint for credentials
15. Ensure only authenticated users can access their vault
16. Validate input and sanitize data
17. Write unit tests for encryption logic
18. Write integration tests for API endpoints
19. Write API documentation
20. Add usage examples
21. Add Dockerfile for easy setup
22. Add docker-compose for easy setup
23. Prepare for deployment (Heroku, Render, etc.)
