import React from 'react';
import { useEffect, useState } from 'react';

import { initAuth0, loginWithMagicLink, callBackend, logout, getAuthToken } from './auth/auth0-logic';

function App() {
  const [email, setEmail] = useState('');
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState(null);
  const [error, setError] = useState('');

  useEffect(() => {
    const checkAuth = async () => {
      await initAuth0();
      const token = await getAuthToken();
      setIsAuthenticated(!!token);
      setLoading(false);
    };
    checkAuth();
  }, []);

  const handleLogin = async (e) => {
    e.preventDefault();
    setError('');
    if (!email || !email.includes('@')) {
      setError('Please enter a valid email');
      return;
    }
    try {
      await loginWithMagicLink(email);
    } catch (err) {
      setError('Login failed. Try again.');
      console.error(err);
    }
  };

  const fetchProtected = async () => {
    setData(null);
    setError('');
    try {
      const result = await callBackend('/protected');
      setData(result);
    } catch (err) {
      setError(err.message || 'Access denied');
    }
  };

  if (loading) {
    return <div style={styles.container}>Loading...</div>;
  }

  return (
    <div style={styles.container}>
      <h1 style={styles.title}>🔐 Secure App</h1>

      {!isAuthenticated ? (
        <div style={styles.card}>
          <h2>Sign In with Magic Link</h2>
          <form onSubmit={handleLogin} style={styles.form}>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="your@email.com"
              style={styles.input}
              required
            />
            <button type="submit" style={styles.button}>
              Send Magic Link
            </button>
          </form>
          {error && <p style={styles.error}>{error}</p>}
        </div>
      ) : (
        <div style={styles.card}>
          <p>✅ You're logged in!</p>
          <div>
            <button onClick={fetchProtected} style={styles.button}>
              Call Protected Route
            </button>
            <button onClick={logout} style={{ ...styles.button, background: '#d32f2f', marginLeft: '10px' }}>
              Logout
            </button>
          </div>
          {data && (
            <pre style={styles.pre}>
              {JSON.stringify(data, null, 2)}
            </pre>
          )}
          {error && <p style={styles.error}>{error}</p>}
        </div>
      )}
    </div>
  );
}

// Minimal styles
const styles = {
  container: {
    fontFamily: 'Arial, sans-serif',
    padding: '40px',
    textAlign: 'center',
    maxWidth: '600px',
    margin: '0 auto'
  },
  title: {
    color: '#1976d2'
  },
  card: {
    border: '1px solid #ddd',
    borderRadius: '8px',
    padding: '20px',
    backgroundColor: '#f9f9f9'
  },
  form: {
    marginTop: '10px'
  },
  input: {
    padding: '10px',
    fontSize: '16px',
    width: '250px',
    border: '1px solid #ccc',
    borderRadius: '4px'
  },
  button: {
    padding: '10px 15px',
    fontSize: '16px',
    marginLeft: '10px',
    backgroundColor: '#1976d2',
    color: 'white',
    border: 'none',
    borderRadius: '4px',
    cursor: 'pointer'
  },
  error: {
    color: '#d32f2f',
    marginTop: '10px'
  },
  pre: {
    textAlign: 'left',
    background: '#eee',
    padding: '15px',
    borderRadius: '4px',
    overflow: 'auto',
    fontSize: '12px'
  }
};

export default App;