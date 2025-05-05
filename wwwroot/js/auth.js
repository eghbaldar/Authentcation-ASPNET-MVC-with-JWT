(function () {
    const originalFetch = window.fetch;

    window.fetch = async function (url, options) {
        options = options || {};
        options.credentials = options.credentials || 'include';
        options.headers = options.headers || {};
        options.headers['X-Requested-With'] = 'XMLHttpRequest';

        let response = await originalFetch(url, options);

        // Avoid infinite loop: if the failing call is already /auth/RefreshToken, don't retry
        const isRefreshing = url.includes('/auth/RefreshToken');
        const isUnauthorized = response.status === 401 || (response.redirected && response.url.includes('/Auth/Login'));

        if (!isRefreshing && isUnauthorized) {
            return await refreshTokenAndRetry(url, options, response);
        }

        return response;
    };

    // Refresh token on first page load if redirected to login
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
                const returnUrl = urlParams.get('ReturnUrl') || '/';
                window.location.href = decodeURIComponent(returnUrl);
            } else {
                console.error('Token refresh failed:', await refreshResponse.text());
            }
        }
    });

    async function refreshTokenAndRetry(url, options, originalResponse) {
        try {
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
            }
        } catch (e) {
            console.error("Refresh retry failed hard:", e);
        }

        // Redirect to login only once!
        window.location.href = '/Auth/Login';
        return originalResponse;
    }
})();
