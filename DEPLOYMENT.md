# Deployment Guide for CodeCollab

## Prerequisites

1. **MongoDB Database**
   - Create a MongoDB Atlas account (free tier available)
   - Create a cluster and get the connection string
   - Or use a local MongoDB instance

2. **Google OAuth Setup**
   - Go to [Google Cloud Console](https://console.cloud.google.com/)
   - Create a new project or select existing one
   - Enable Google+ API
   - Create OAuth 2.0 credentials
   - Add authorized redirect URIs:
     - For localhost: `http://localhost:3002/auth/google/callback`
     - For Vercel: `https://your-app-name.vercel.app/auth/google/callback`

## Environment Variables

Copy `.env.example` to `.env` and fill in your values:

```bash
# Required for both localhost and Vercel
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/codecollab
SESSION_SECRET=your-super-secret-session-key-here
CLIENT_ID=your-google-client-id.apps.googleusercontent.com
CLIENT_GOOGLE_SECRET=your-google-client-secret
```

## Local Development

1. Install dependencies:
   ```bash
   npm install
   ```

2. Start the development server:
   ```bash
   npm start
   ```

3. Open `http://localhost:3002` in your browser

## Vercel Deployment

### Option 1: Deploy via GitHub (Recommended)

1. Push your code to GitHub
2. Connect your GitHub repository to Vercel
3. Set environment variables in Vercel dashboard:
   - `MONGODB_URI`
   - `SESSION_SECRET`
   - `CLIENT_ID`
   - `CLIENT_GOOGLE_SECRET`
4. Deploy automatically on every push

### Option 2: Deploy via Vercel CLI

1. Install Vercel CLI:
   ```bash
   npm i -g vercel
   ```

2. Login to Vercel:
   ```bash
   vercel login
   ```

3. Deploy:
   ```bash
   vercel
   ```

4. Set environment variables:
   ```bash
   vercel env add
   ```

## Important Notes

- **Google OAuth**: Make sure to add both localhost and production URLs to your Google OAuth authorized redirect URIs
- **MongoDB**: Use MongoDB Atlas for production, local MongoDB for development
- **Session Secret**: Generate a strong random string for production
- **HTTPS**: Vercel automatically provides HTTPS, which is required for Google OAuth in production

## Troubleshooting

### 1. Google OAuth redirecting to localhost in production

This is the most common issue. To fix it:

**A. Check Google Cloud Console Redirect URIs:**
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Navigate to APIs & Services > Credentials
3. Click on your OAuth 2.0 Client ID
4. In "Authorized redirect URIs", ensure you have BOTH:
   - `http://localhost:3002/auth/google/callback` (for development)
   - `https://your-app-name.vercel.app/auth/google/callback` (for production)

**B. Set explicit callback URL in Vercel:**
1. In Vercel dashboard, go to your project settings
2. Go to Environment Variables
3. Add: `GOOGLE_CALLBACK_URL` = `https://your-app-name.vercel.app/auth/google/callback`
4. Redeploy your application

**C. Verify environment detection:**
Check your Vercel deployment logs to see what callback URL is being used:
```
Environment detection:
- VERCEL_ENV: production
- VERCEL_URL: your-app-name.vercel.app
- NODE_ENV: production
- isVercelProduction: true
- Google OAuth Callback URL: https://your-app-name.vercel.app/auth/google/callback
```

### 2. Authentication not working
   - Check Google OAuth redirect URIs (see above)
   - Verify environment variables are set correctly in Vercel dashboard
   - Check browser developer tools for errors
   - Ensure Google OAuth credentials are valid

### 3. Database connection issues
   - Verify MongoDB URI is correct
   - Check MongoDB Atlas IP whitelist (use 0.0.0.0/0 for all IPs)
   - Ensure database user has proper permissions

### 4. Session issues
   - Generate a new session secret
   - Clear browser cookies
   - Check cookie settings in browser developer tools
