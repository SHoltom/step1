export default {
    server: {
      port: 3000,
      open: true,
      proxy: {
        '/api': {
          target: 'http://localhost:8000',
          changeOrigin: true
        }
      }
    },
    define: {
      'process.env': {
        VITE_AUTH0_DOMAIN: process.env.VITE_AUTH0_DOMAIN,
        VITE_AUTH0_CLIENT_ID: process.env.VITE_AUTH0_CLIENT_ID,
        VITE_AUTH0_AUDIENCE: process.env.VITE_AUTH0_AUDIENCE,
        VITE_AUTH0_REDIRECT_URI: process.env.VITE_AUTH0_REDIRECT_URI || window.location.origin
      }
    }
  }