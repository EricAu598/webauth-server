# Deploying Face ID Test Server to Vercel

This guide explains how to deploy the Face ID Test Server to Vercel.

## Prerequisites

1. A [Vercel account](https://vercel.com/signup)
2. [Vercel CLI](https://vercel.com/docs/cli) installed (optional, for local testing)
3. [Git](https://git-scm.com/downloads) installed

## Setup Steps

### 1. Prepare Your Project for Vercel

The following files have been added to make the project compatible with Vercel:

- `package.json`: Defines dependencies and scripts
- `vercel.json`: Configures how Vercel builds and routes the application
- `index.js`: Adapted version of the server for Vercel's serverless environment

### 2. Set Up Vercel KV (Redis)

Since the original server uses Redis, you'll need to set up Vercel KV:

1. Go to your Vercel dashboard
2. Select your project
3. Go to "Storage" tab
4. Click "Create" and select "KV Database"
5. Follow the setup instructions
6. Connect your KV database to your project

### 3. Deploy to Vercel

#### Option 1: Deploy via Vercel Dashboard

1. Push your code to a Git repository (GitHub, GitLab, or Bitbucket)
2. Log in to your Vercel dashboard
3. Click "New Project"
4. Import your repository
5. Configure the project:
   - Build Command: Leave as default
   - Output Directory: Leave as default
   - Environment Variables: Add any necessary environment variables
6. Click "Deploy"

#### Option 2: Deploy via Vercel CLI

1. Install Vercel CLI: `npm i -g vercel`
2. Login to Vercel: `vercel login`
3. Deploy: `vercel`
4. Follow the prompts

### 4. Environment Variables

Set these environment variables in your Vercel project settings:

- `ALLOWED_ORIGIN`: Your frontend domain (e.g., `https://yourdomain.com`)
- `NODE_ENV`: Set to `production`

### 5. Testing Your Deployment

After deployment, your Face ID server will be available at the URL provided by Vercel.

## Important Notes

1. **WebAuthn Requirements**: WebAuthn requires HTTPS, which Vercel provides by default.

2. **Adapting the Code**: The provided `index.js` is a template. You'll need to adapt all Redis operations to use Vercel KV.

3. **Limitations**: Vercel has a 10-second execution limit for serverless functions. If your authentication process takes longer, consider optimizing it.

4. **Statelessness**: Vercel functions are stateless. All state must be stored in Vercel KV or another external service.

## Troubleshooting

- **Deployment Fails**: Check the Vercel build logs for errors
- **Redis Connection Issues**: Verify your Vercel KV setup and environment variables
- **CORS Errors**: Make sure your CORS settings include your frontend domain 