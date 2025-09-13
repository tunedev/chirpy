# Chirpy 🐦

[](https://golang.org/)
[](https://opensource.org/licenses/MIT)

Chirpy is a backend API for a Twitter-like social media service, built entirely in Go. It serves as a practical demonstration of building a modern, robust, and secure web service using the Go standard library and best practices.

## Table of Contents

- [What It Does](https://www.google.com/search?q=%23what-it-does)
- [Why It's Cool](https://www.google.com/search?q=%23why-its-cool)
- [Getting Started](https://www.google.com/search?q=%23getting-started)
  - [Prerequisites](https://www.google.com/search?q=%23prerequisites)
  - [Installation & Running](https://www.google.com/search?q=%23installation--running)
- [API Endpoints](https://www.google.com/search?q=%23api-endpoints)

---

## What It Does

Chirpy provides the complete backend functionality for a social media application. Users can sign up, log in, post short messages (or "chirps"), and manage their content.

### Key Features

- **Full User Authentication**: Secure user sign-up and login using JWT access tokens and refresh tokens.
- **CRUD for Chirps**: Users can create, read, and delete their own chirps.
- **Content Moderation**: A built-in middleware automatically sanitizes chirps by replacing profane words.
- **Webhook Integration**: Listens for webhooks from an external service (Polka) to handle user account upgrades (e.g., subscribing to "Chirpy Red").
- **Admin Dashboard**: Includes administrative endpoints to view site metrics and manage the application state in a development environment.
- **Database Integration**: Persists all data in a PostgreSQL database, managed with `sqlc` for type-safe queries.

---

## Why It's Cool

This project isn't just another to-do list app. It's a comprehensive showcase of the skills required to build a real-world Go backend service from the ground up.

- **Standard Library First**: The web server is built using only Go's native `net/http` package, demonstrating a solid understanding of the language's core features without relying on a framework.
- **Modern Auth Patterns**: Implements a secure and state-of-the-art authentication system with short-lived access tokens and long-lived, revocable refresh tokens.
- **Clean API Design**: The API is designed to be RESTful and intuitive, with clear separation of concerns.
- **Middleware Architecture**: Leverages Go's middleware pattern for handling authentication, request validation, and metrics collection in a clean, composable way.
- **Secure & Type-Safe Database Code**: Uses `sqlc` to generate fully type-safe Go code from raw SQL queries, preventing SQL injection and eliminating runtime errors.

---

## Getting Started

Follow these instructions to get a local instance of Chirpy up and running.

### Prerequisites

- **Go**: A recent version of Go (1.21+).
- **PostgreSQL**: A running instance of PostgreSQL.

### Installation & Running

1. **Clone the repository:**

   ```sh
   git clone https://github.com/your-username/chirpy.git
   cd chirpy
   ```

2. **Set up the database:**
   Ensure your PostgreSQL server is running. You will need the database connection URL for the next step.

3. **Configure environment variables:**
   Create a `.env` file in the root of the project. This file will hold your database connection string and application secrets.

   ```env
   # Example .env file

   # Your PostgreSQL connection string
   DB_URL="postgres://user:password@localhost:5432/chirpy?sslmode=disable"

   # A strong, random string for signing JWTs
   JWT_SECRET="a-very-secret-key-that-you-should-generate"

   # The API key for validating Polka webhooks
   POLKA_KEY="your-polka-api-key"
   ```

4. **Run the server:**
   Execute the `main.go` file to start the web server.

   ```sh
   go run main.go
   ```

   The server will start and listen for requests on port `8021`. You can verify it's running by hitting the health check endpoint:

   ```sh
   curl http://localhost:8021/api/healthz
   # Expected output: OK
   ```

---

## API Endpoints

The following is a summary of the available API endpoints.

| Method   | Endpoint                | Description                                        | Auth Required |
| -------- | ----------------------- | -------------------------------------------------- | :-----------: |
| `GET`    | `/api/healthz`          | Checks if the service is running.                  |      No       |
| `GET`    | `/admin/metrics`        | Displays the number of website visits.             |      No       |
| `POST`   | `/admin/reset`          | Resets the database (dev environment only).        |      No       |
| `POST`   | `/api/users`            | Creates a new user account.                        |      No       |
| `PUT`    | `/api/users`            | Updates the authenticated user's email/password.   |    **Yes**    |
| `POST`   | `/api/login`            | Logs a user in, returns access and refresh tokens. |      No       |
| `POST`   | `/api/refresh`          | Issues a new access token using a refresh token.   |      No       |
| `POST`   | `/api/revoke`           | Revokes a refresh token.                           |      No       |
| `POST`   | `/api/chirps`           | Creates a new chirp.                               |    **Yes**    |
| `GET`    | `/api/chirps`           | Gets all chirps. Supports `?author_id` & `?sort`.  |      No       |
| `GET`    | `/api/chirps/{chirpID}` | Gets a single chirp by its ID.                     |      No       |
| `DELETE` | `/api/chirps/{chirpID}` | Deletes a chirp if you are the author.             |    **Yes**    |
| `POST`   | `/api/polka/webhooks`   | Endpoint for receiving Polka webhooks.             |    API Key    |
