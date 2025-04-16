(function () {
    //alert('auth.js loaded'); // Debug

    // Intercept fetch requests
    const originalFetch = window.fetch;
    window.fetch = async function (url, options) {
        options = options || {};
        options.credentials = options.credentials || 'include';
        options.headers = options.headers || {};
        options.headers['X-Requested-With'] = 'XMLHttpRequest';

        //alert(`Fetching: ${url}`); // Debug
        let response = await originalFetch(url, options);

        if (response.status === 401 || (response.redirected && response.url.includes('/Auth/Login'))) {
            //alert("401 or redirect detected, attempting to refresh token");
            return await refreshTokenAndRetry(url, options, response);
        }

        return response;
    };

    // Handle page loads redirecting to /Auth/Login
    window.addEventListener('load', async () => {
        if (window.location.href.includes('/Auth/Login?ReturnUrl=')) {
            //alert('Detected redirect to /Auth/Login, attempting to refresh token'); // Debug

            const refreshResponse = await fetch('/auth/RefreshToken', {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                }
            });

            //alert(`Refresh token response: ${refreshResponse.status}`); // Debug

            if (refreshResponse.ok) {
                //alert('Token refreshed, redirecting to ReturnUrl'); // Debug
                const urlParams = new URLSearchParams(window.location.search);
                const returnUrl = urlParams.get('ReturnUrl') || '/home/king';
                window.location.href = decodeURIComponent(returnUrl);
            } else {
                console.error('Token refresh failed:', await refreshResponse.text()); // Debug
                //alert('Failed to refresh token. Please log in again.');
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

        //alert(`Refresh token response: ${refreshResponse.status}`); // Debug

        if (refreshResponse.ok) {
            //alert('Token refreshed successfully'); // Debug
            if (!url.includes('/api/') && !options.headers['Content-Type']?.includes('application/json')) {
                //alert('Reloading page after token refresh'); // Debug
                window.location.reload();
                return originalResponse;
            }
            return await originalFetch(url, options);
        } else {
            //console.error('Token refresh failed:', await refreshResponse.text()); // Debug
            window.location.href = '/Auth/Login';
            return originalResponse;
        }
    }
})();