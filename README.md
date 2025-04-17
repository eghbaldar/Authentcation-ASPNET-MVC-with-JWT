# 🔐 ASP.NET Core MVC JWT Authentication & Role-Based Authorization
Coded by: Alimohammad Eghbaldar
Source: https://kingeto.ir

A modern ASP.NET Core MVC web application with **JWT-based authentication**, **refresh token system**, and **role-based access control**. This project demonstrates secure login, token handling, and cookie-based session management – built with both developers and real-world application needs in mind.

---

## 🎯 Project Goals

- ✅ Provide a **clean, secure login system** using **JWT tokens** instead of cookies alone.
- ✅ Use **refresh tokens** to keep users logged in without re-entering credentials.
- ✅ Handle **role-based access** so users only see what they're allowed to.
- ✅ Mix **MVC** for UI with **Web API** for backend logic — the best of both worlds.
- ✅ Be a **reference for other developers** learning secure authentication in ASP.NET Core.

---

## ⚙️ Tech Stack

| Layer              | Technology                         |
|-------------------|-------------------------------------|
| Backend           | **ASP.NET Core MVC (.NET 6/7)**     |
| Auth              | **JWT (Json Web Token)**            |
| Frontend          | HTML5 + Bootstrap + jQuery          |
| API Communication | `fetch()` with JSON body            |
| Token Storage     | HttpOnly **cookies** (refresh token)|
| Security          | `[Authorize(Roles = "...")]`       |
| DB Access (optional) | Entity Framework Core (extensible) |

---

## 🔑 Features

- 🔐 **Secure Login API** that returns access & refresh tokens
- 🍪 **Refresh token** is stored in an **HttpOnly cookie**
- 🔁 Refresh token system to re-issue access tokens without login
- 👮‍♂️ **Role-based page protection** using `[Authorize]`
- 🚫 Customizable **Access Denied** redirection
- ⚠️ Catches expired access tokens and handles auto-login via refresh
- 🧠 Stateless server auth — no sessions stored on server
- 🎯 Designed for both **single-user** and **multi-role systems**

---

## 🖥️ Project Structure
/Controllers AuthController.cs ← API for login, token issuing HomeController.cs ← MVC views for authenticated pages
/Views /Home/ ← UI pages (protected or public) /Shared/_Layout.cshtml ← Common layout
/wwwroot/js login.js ← Login function using fetch()
/wwwroot/js auth.js ← Handles auth logic: access token refresh, cookie check, etc.
/Models UserModel.cs ← Login request model
/Program.cs / Startup.cs ← JWT + Auth config


---

## 🚀 Getting Started

1. **Clone the project**
   ```
   git clone https://github.com/your-username/your-repo-name.git
   cd your-repo-name   
2. **Setup your MS SQL SERVER**
   ```
   add-migratio 'first migration'
   update-database
3. Insert two records like the following data in User table
   ```
   INSERT INTO [dbo].[Users]([Id],[Name],[Email],[Password],[Role])
     VALUES
		('c96a857e-a71b-4699-b42c-e49d7e186835','eghbaldar','eghbaldar@gmail.com','1234','Admin'),
		('c96a857e-a71b-4199-b42c-e49d7e181235','you','you@gmail.com','1234','User')
3. Build and run
4. First login and then surf on other pages!
