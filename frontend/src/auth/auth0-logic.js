
import { createAuth0Client } from '@auth0/auth0-spa-js';

let auth0Client = null;

/**
 * Initialize Auth0 client
 */
export const initAuth0 = async () => {
  try {
    auth0Client = await createAuth0Client({
      domain: import.meta.env.VITE_AUTH0_DOMAIN,
      client_id: import.meta.env.VITE_AUTH0_CLIENT_ID,
      authorization_params: {
        redirect_uri: import.meta.env.VITE_AUTH0_REDIRECT_URI || window.location.origin,
        audience: import.meta.env.VITE_AUTH0_AUDIENCE
      },
      timeoutMs: 5000,
      cacheLocation: 'localstorage'
    });

    // Handle redirect callback
    if (window.location.search.includes("code=")) {
      try {
        const result = await auth0Client.handleRedirectCallback();
        window.history.replaceState({}, document.title, "/");
        return result;
      } catch (callbackError) {
        console.error("Error handling redirect callback:", callbackError);
        throw callbackError;
      }
    }
    return auth0Client;
  } catch (err) {
    console.error("Auth0 init failed:", err);
    throw err;
  }
};

/**
 * Login with magic link (email)
 */
export const loginWithMagicLink = async (email) => {
  if (!auth0Client) throw new Error("Auth0 not initialized");

  try {
    await auth0Client.loginWithRedirect({
      authorization_params: {
        connection: 'email',
        login_hint: email,
        screen_hint: 'signup'
      },
      timeoutMs: 5000
    });
  } catch (err) {
    console.error("Error initiating magic link login:", err);
    throw err;
  }
};

/**
 * Get Auth0 access token silently
 */
export const getAuthToken = async () => {
  if (!auth0Client) return null;
  try {
    return await auth0Client.getTokenSilently();
  } catch (err) {
    console.error("Token fetch failed:", err);
    return null;
  }
};

/**
 * Call backend API with JWT and CSRF
 */
export const callBackend = async (endpoint, options = {}) => {
  const token = await getAuthToken();
  if (!token) throw new Error("Not authenticated");

  const headers = {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json',
    ...options.headers
  };

  // Add CSRF token if available
  const csrfToken = getCookie('csrf_token')?.split(':')[0]; // Extract token part
  if (csrfToken) {
    headers['X-CSRF-Token'] = csrfToken;
  }

  const url = `${import.meta.env.VITE_BACKEND_URL}${endpoint}`;
  const res = await fetch(url, { ...options, headers });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `HTTP ${res.status}`);
  }

  return await res.json();
};

/**
 * Logout
 */
export const logout = async () => {
  if (!auth0Client) return;

  try {
    // Clear local auth state
    await auth0Client.logout({
      logoutParams: {
        returnTo: window.location.origin
      }
    });

    // Optional: Call backend to destroy session
    await fetch(`${import.meta.env.VITE_BACKEND_URL}/logout`, {
      method: 'POST',
      credentials: 'include'  // Send session cookie
    });
  } catch (err) {
    console.error("Logout failed:", err);
    // Don't throw error on logout - it's just cleanup
  } finally {
    localStorage.removeItem('auth0_token');
    sessionStorage.clear();
    window.location.href = "/";
  }
};

/**
 * Helper: Read cookie by name
 */
function getCookie(name) {
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) return parts.pop().split(';').shift();
}