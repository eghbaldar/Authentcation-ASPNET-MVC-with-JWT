# 🔐 ASP.NET Core Auth System – JWT + Cookie Authentication Combo

This project is a comprehensive implementation of **authentication in ASP.NET Core**, demonstrating **both Cookie Authentication** (traditional server-side auth) and **JWT Bearer Token Authentication** (modern, API-focused).

It's designed for flexibility and real-world scenarios, supporting frontend and backend flows such as Razor pages, AJAX calls, and modern frontend frameworks like React or Angular.

---

## 📌 Features

- ✅ **Login with access & refresh tokens**
- ✅ **Secure HTTP-only refresh token cookie**
- ✅ **Token refreshing logic**
- ✅ **Support for both Cookie & JWT authentication**
- ✅ **Role-based access control**
- ✅ **Clean architecture & extensible design**
- ✅ **Interceptor-based auto token refresh**

---

## 🚀 Quick Overview

| Endpoint              | Auth Method      | Description                                          |
|-----------------------|------------------|------------------------------------------------------|
| `/home/AdminPage`     | Cookie Auth       | Accessible to users with `Admin` role               |
| `/home/UserPage`      | Cookie Auth       | Accessible to users with `User` role                |
| `/home/AllRoles`      | Cookie Auth       | Accessible with valid cookie                        |
| `/home/AllRolesBearer`| JWT Bearer Auth   | Only accessible via AJAX with Bearer token header   |

---

## 🔁 Token Flow

### Step-by-Step Flow:

1. **Login**
   - Client sends credentials via `/auth/login`
   - Server returns:
     - `accessToken` → Stored in a normal JS cookie (accessible by JavaScript)
     - `refreshToken` → Sent as `HttpOnly` cookie (invisible to JavaScript)

2. **Authenticated Requests**
   - JS sends `accessToken` in `Authorization: Bearer <token>` header (for JWT)
   - Or lets browser send cookies automatically (for Cookie Auth)

3. **Token Expired?**
   - Custom `fetch()` interceptor detects 401 errors
   - Automatically requests new token via `/auth/RefreshToken`
   - Retries the original request

---

## 🧠 Deep Dive Notes

### NOTE [1] – What's a Refresh Token?

- It's like a **VIP backstage pass** 🎟️
- Lets your app get a new access token **without logging in again**
- Your short-lived access token expires in ~15–60 minutes
- Stored in an `HttpOnly` cookie, invisible to JS

---

### NOTE [2] – UTC vs Local Time

Using this line:

```csharp
Expires = DateTimeOffset.UtcNow.AddMinutes(30)
```
You're seeing UTC time (e.g., 09:02) even if your local time is 12:33 PM.

NOTE [3] – Login: Dual Cookies
After login:
✅ authToken (access token): JS-accessible cookie
✅ refreshToken: Secure HTTP-only cookie
Flow:
- JS → login API
- Backend → generates both tokens
- Frontend stores authToken, backend sets refreshToken in response

NOTE [4] – Cookie Roles

Cookie	Visibility	Purpose
authToken	JavaScript	Access token
refreshToken	HTTP-only	Refresh token logic
| Cookie              | Visibility | Purpose |
|-----------------------|--------------------------------|------|
| authToken	     | JavaScript	 | 	Access token |
| refreshToken      | HTTP-only	       | Refresh token logic |


NOTE [5] – credentials: 'include'
This ensures all cookies (including secure ones) are sent with fetch():
```
fetch("/home/king", {
  method: "GET",
  credentials: "include"
});
```

NOTE [6] – [Authorize] Pages
The /home/king and other pages use:
```
[Authorize]
```

NOTE [7] – Why Build Refresh Logic?
Even with cookies, browsers do not auto-refresh expired tokens. You must handle it manually with logic like fetchWithRefresh().

NOTE [8] – Refresh Token Storage
🧱 Using a simple dictionary in-memory?
⚠️ Not safe for production. Refresh tokens will be lost on server restart.
✅ Real-world alternatives:
- Use a persistent database
- Use Redis or distributed cache
- Store expiration timestamps securely

NOTE [9] – Using Both Cookie & JWT? YES!
Using both auth schemes is wise and flexible.
---
## 🚀 Quick Overview

| User Case              | Auth Schem |
|-----------------------|--------------------------------|
| Server-rendered pages (e.g., Razor)	     | Cookie Auth |
| `/home/UserPage`      | Cookie Auth       | JWT Auth |
---

NOTE [10] – Why return View() Won't Work With JWT?
Views require cookies and server state. JWT is stateless, designed for API-like calls.

✅ Instead: return Json(...) or data for frontend rendering.

Security Tips
- Always use HTTPS in production
- Mark cookies as Secure and SameSite=Strict or Lax
- Rotate refresh tokens on each use
- Invalidate tokens on logout or suspicious activity
- Use token expiration + IP + user-agent fingerprinting for more control

📂 Folder Structure (Example)
```
/Controllers
  └── AuthController.cs
  └── HomeController.cs
/Middleware
/Models
/Services
/Views
  └── Home/
  └── Shared/
Program.cs
Startup.cs
README.md
```

🤝 Contributing
PRs are welcome if you'd like to extend or improve this template!

🔗 License
MIT – Do whatever you like 😄

