# Secure JWT Authentication – ASP.NET Core MVC

A production-ready mini project demonstrating secure JWT authentication
using ASP.NET Core MVC with Access Tokens, Refresh Tokens, and Cookies.

## Features
- JWT Authentication
- HttpOnly Cookie-based auth
- Refresh Token with rotation
- Auto token refresh
- Role-based authorization (Admin/User)
- Secure logout with token revocation

## Tech Stack
- ASP.NET Core MVC
- Entity Framework Core
- SQL Server
- JWT (Access + Refresh Token)
- Git & GitHub

## How to Run
1. Clone repo
2. Update connection string
3. Run migrations
4. `dotnet run`

## Default Users
| Username | Password | Role |
|--------|----------|------|
| admin | Admin@123 | Admin |
| user | User@123 | User |

## Security Highlights
- Short-lived access tokens
- Refresh token rotation
- HttpOnly & Secure cookies
- Server-side logout

## Author
Built for learning secure authentication in real-world MVC apps.
