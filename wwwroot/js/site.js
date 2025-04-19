//NOTE: in your controller: return View(); // ❌ won't work properly with fetch
async function runFunctionIsProtectedByJWT(api) {
    const token = localStorage.getItem("authToken"); // or sessionStorage, or a JS variable
    const response = await fetch(api, {
        method: "GET",
        headers: {
            "Authorization": "Bearer " + token
        }
    });
    if (response.ok) {
        const data = await response.json();
        alert(JSON.stringify(data));  // Handle the response data
    } else {
        alert("Unauthorized or error occurred");
        window.location = "/";
    }
}
async function Logout() {
    localStorage.clear();
    sessionStorage.clear(); // optional
    window.location.href = "/auth/Logout"; // or homepage
}