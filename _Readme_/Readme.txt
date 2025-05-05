NOTE [1]:
What's a Refresh Token?
A Refresh Token is like the VIP backstage pass for your app's authentication system.
Your JWT access token is short-lived (e.g., 15–60 mins).
When it expires, instead of making the user log in again, you use a Refresh Token to get a new access token.
Frontend stores the access token in a regular cookie, accessible by JavaScript, and does not handle the refreshToken cookie.

NOTE[2]:
The reason you're seeing an earlier expiration time (e.g., 09:02) even though your local time is 12:33 PM is because you're using:
Expires = DateTimeOffset.UtcNow.AddMinutes(...)
DateTimeOffset.UtcNow gives the current time in UTC (not your local time).


NOTE[3]:
When you log in for the first time, two cookies will be created — one from the client-side (your JavaScript code) and one from the server-side (through HTTP response).
Here's the flow:
> Frontend (Client-Side) sends the login request to the backend (e.g., with username and password).
>Backend (Server-Side):
>>Validates the credentials.
>>Generates two tokens:
>>>Access token (JWT) — short-lived token for authenticating requests.
>>>Refresh token — long-lived token to refresh the access token when it expires.
>The Backend sends back the following:
>>Access token (in the response body) — The client (your JavaScript) will take this token and set it in a cookie named authToken.
>>Refresh token (in the HTTP-only cookie) — The backend will send this token to the client as an HTTP-only cookie, which JavaScript cannot access.

NOTE[4]:
> Cookie (authToken) is for short-lived access and can be accessed by JavaScript.
> Cookie (refreshToken) is for long-lived token refreshing and is stored as HTTP-only by the backend, which JavaScript cannot read.
>> If the access token is not expired yet, you try to visit /home/king directly in the browser (or any similar authorized page), the browser will send your cookies automatically, including authToken (access token) and refreshToken (refresh token).
>> If the access token is expired, the server will return 401 Unauthorized, and at this point, the browser doesn’t automatically know how to refresh the token. That’s when you need to use fetchWithRefresh to handle token refreshing and retry the request automatically.

NOTE[5]:
>When credentials: 'include' is set:
>It tells fetch() to automatically send all cookies (including refreshToken and authToken) to your backend 

NOTE[6]:
The /home/king page is marked with [Authorize], which relies on the authentication scheme configured in Program.cs.

NOTE[7]:
Why do we even need RefreshToken() if we're using cookies?
Because the browser won't auto-refresh your JWT — you must build that logic.

NOTE[8]:
⚠️ A Real-World Note
In production, this dictionary-based store is not persistent. If the server restarts, the tokens are lost.
🧱 Better alternatives:
Store in database.
Use distributed cache like Redis.
Add expiration timestamps to refresh tokens.

NOTE[9]:
using both Cookie Authentication and JWT (Bearer Token) Authentication in the same ASP.NET Core project is not only feasible, but also very wise and flexible in many scenarios.
in this project, we use
1) JWT Auth => for: /home/AllRolesBearer
2) Cookie Auth => for: /home/AdminPage & /home/UserPage & /home/AllRoles

NOTE[10]:
in your controller: return View(); // ❌ won't work properly with fetch
Why not return a View with JWT?
JWT works without cookies and doesn't integrate automatically into Razor view rendering or MVC routing. It's mainly used for API-style apps (e.g., React, Angular, Vue, or raw JS frontend).

NOTE[11]:
what's difference between those?
options.ExpireTimeSpan = TimeSpan.FromDays(15);
options.Cookie.MaxAge = TimeSpan.FromDays(15);

> options.ExpireTimeSpan
Belongs to: CookieAuthenticationOptions
Purpose: Determines how long the authentication ticket (claims, identity, etc.) is valid after being issued.
This means the user must re-authenticate after 15 days.

> options.Cookie.MaxAge
Belongs to: CookieBuilder (a sub-property of the options)
Purpose: Sets the Max-Age attribute in the cookie itself, defining how long the browser should keep the cookie.
Implication: If this isn't set, the cookie becomes a session cookie (deleted when the browser closes).
This means the browser: “Keep this cookie for 15 days.”


