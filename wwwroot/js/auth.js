//////////////////////////////////////////////////////////////////////////////////////////
//
// Frontend Interceptor
// This script improves UX by detecting expired sessions and refreshing tokens without forcing the user to log in again.
//
//////////////////////////////////////////////////////////////////////////////////////////

(function () {    
    // Intercept fetch requests
    const originalFetch = window.fetch;
    window.fetch = async function (url, options) {
        options = options || {};
        options.credentials = options.credentials || 'include';
        options.headers = options.headers || {};
        options.headers['X-Requested-With'] = 'XMLHttpRequest';
        let response = await originalFetch(url, options);
        if (response.status === 401 || (response.redirected && response.url.includes('/Auth/Login'))) {
            return await refreshTokenAndRetry(url, options, response);
        }
        return response;
    };
    // Handle page loads redirecting to /Auth/Login
    window.addEventListener('load', async () => {
        if (window.location.href.includes('/Auth/Login?ReturnUrl=')) {
            const refreshResponse = await fetch('/auth/RefreshToken', {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                }
            });
            if (refreshResponse.ok) {
                const urlParams = new URLSearchParams(window.location.search);
                const returnUrl = urlParams.get('ReturnUrl') || '/home/king';
                window.location.href = decodeURIComponent(returnUrl);
            } else {
                console.error('Token refresh failed:', await refreshResponse.text()); // Debug
            }
        }
    });
    async function refreshTokenAndRetry(url, options, originalResponse) {
        const refreshResponse = await fetch('/auth/RefreshToken', {
            method: 'POST',
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            }
        });
        if (refreshResponse.ok) {
            if (!url.includes('/api/') && !options.headers['Content-Type']?.includes('application/json')) {
                window.location.reload();
                return originalResponse;
            }
            return await originalFetch(url, options);
        } else {
            window.location.href = '/Auth/Login';
            return originalResponse;
        }
    }
})();