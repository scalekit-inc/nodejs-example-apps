// Authentication helper for managing tokens
class AuthManager {
  constructor() {
    // Check tokens on initialization
    this.checkAndRefreshTokens();
  }

  // Store access token in cookie
  setAccessToken(accessToken, expiresIn) {
    const accessTokenExpiry = new Date();
    // Convert expiresIn from seconds to milliseconds and subtract 60 seconds for safety margin
    accessTokenExpiry.setTime(
      accessTokenExpiry.getTime() + (expiresIn - 60) * 1000
    );

    // Set access token with expiry
    document.cookie = `accessToken=${accessToken}; expires=${accessTokenExpiry.toUTCString()}; path=/; SameSite=Strict`;
  }

  // Get a cookie by name
  getCookie(name) {
    const cookies = document.cookie.split(';');
    for (let i = 0; i < cookies.length; i++) {
      const cookie = cookies[i].trim();
      if (cookie.startsWith(name + '=')) {
        return cookie.substring(name.length + 1);
      }
    }
    return null;
  }

  // Delete cookies - now we only manage the access token on client-side
  clearTokens() {
    document.cookie =
      'accessToken=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/; SameSite=Strict';
    // Note: refreshToken is httpOnly and will be cleared by the server
  }

  // Check if access token is expired by decoding it
  isAccessTokenExpired() {
    const accessToken = this.getCookie('accessToken');

    if (!accessToken) {
      return true;
    }

    try {
      // Decode JWT (without validation)
      const base64Url = accessToken.split('.')[1];
      const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
      const payload = JSON.parse(window.atob(base64));

      // Check if token is expired
      const currentTime = Math.floor(Date.now() / 1000);
      return payload.exp < currentTime;
    } catch (error) {
      console.error('Error decoding JWT:', error);
      return true;
    }
  }

  // Get CSRF token for requests
  async getCsrfToken() {
    try {
      const response = await fetch('/api/csrf-token');
      if (!response.ok) {
        throw new Error('Failed to get CSRF token');
      }
      const data = await response.json();
      return data.csrfToken;
    } catch (error) {
      console.error('Error getting CSRF token:', error);
      return null;
    }
  }

  // Refresh tokens if needed before making API requests
  async checkAndRefreshTokens() {
    // If access token is expired, try to refresh
    if (this.isAccessTokenExpired()) {
      try {
        // Call your token refresh endpoint - refreshToken is in httpOnly cookie
        const response = await fetch('/api/refresh-token', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          // No need to send refresh token in body anymore, it's in the cookie
          // Instead, we might need to include CSRF token in production
          credentials: 'same-origin', // Include cookies with the request
        });

        if (!response.ok) {
          throw new Error('Failed to refresh token');
        }

        // Get the new access token
        const data = await response.json();

        // Update access token in cookie
        this.setAccessToken(data.access_token, data.expires_in);
        return true;
      } catch (error) {
        console.error('Error refreshing token:', error);
        // Redirect to login if refresh fails
        this.clearTokens();
        window.location.href = '/sso-login';
        return false;
      }
    }

    return true;
  }

  // Add this token to fetch requests
  async fetchWithAuth(url, options = {}) {
    // Check and refresh token if needed
    const tokenValid = await this.checkAndRefreshTokens();

    if (!tokenValid) {
      return Promise.reject(new Error('Authentication failed'));
    }

    // Get the current access token
    const accessToken = this.getCookie('accessToken');

    // Prepare headers
    const headers = options.headers || {};
    headers['Authorization'] = `Bearer ${accessToken}`;

    // Add CSRF token for mutating operations
    if (
      options.method &&
      options.method !== 'GET' &&
      options.method !== 'HEAD'
    ) {
      try {
        const csrfToken = await this.getCsrfToken();
        if (csrfToken) {
          headers['X-CSRF-Token'] = csrfToken;
        }
      } catch (error) {
        console.error('Error getting CSRF token:', error);
      }
    }

    // Make the request with the token
    return fetch(url, {
      ...options,
      headers,
      credentials: 'same-origin', // Include cookies with the request
    });
  }
}

// Create a global auth manager instance
window.authManager = new AuthManager();

// Add event listener for page load
document.addEventListener('DOMContentLoaded', () => {
  // Check for logout button and attach event handler
  const logoutBtn = document.getElementById('logout-btn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', (e) => {
      e.preventDefault();
      window.authManager.clearTokens();
      window.location.href = '/logout';
    });
  }
});
