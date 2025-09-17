const core = require('@actions/core');
const { sign } = require('jsonwebtoken');
const axios = require('axios');
const { HttpsProxyAgent } = require('https-proxy-agent');

/**
 * Generate JWT token for GitHub App authentication
 */
function generateJWT(appId, privateKey) {
  const now = Math.floor(Date.now() / 1000);
  
  const payload = {
    iat: now - 60, // Issued at time (60 seconds ago to account for clock skew)
    exp: now + (10 * 60), // JWT expires in 10 minutes
    iss: appId // GitHub App ID
  };

  try {
    return sign(payload, privateKey, { algorithm: 'RS256' });
  } catch (error) {
    throw new Error(`Failed to generate JWT: ${error.message}`);
  }
}

/**
 * Create HTTP client with optional proxy configuration
 */
function createHttpClient(proxyUrl, proxyUsername, proxyPassword) {
  const config = {
    timeout: 30000,
    headers: {
      'Accept': 'application/vnd.github.v3+json',
      'User-Agent': 'GitHub-App-Token-Action/1.0'
    }
  };

  if (proxyUrl) {
    core.info(`Configuring proxy: ${proxyUrl}`);
    
    let proxyConfig = proxyUrl;
    if (proxyUsername && proxyPassword) {
      const url = new URL(proxyUrl);
      url.username = proxyUsername;
      url.password = proxyPassword;
      proxyConfig = url.toString();
    }
    
    config.httpsAgent = new HttpsProxyAgent(proxyConfig);
    config.httpAgent = new HttpsProxyAgent(proxyConfig);
  }

  return axios.create(config);
}

/**
 * Get GitHub App installation access token
 */
async function getInstallationToken(httpClient, jwt, installationId, organization) {
  const url = `https://api.github.com/app/installations/${installationId}/access_tokens`;
  
  try {
    core.info(`Requesting installation token for organization: ${organization}`);
    
    const response = await httpClient.post(url, {
      repositories: [], // Empty array means access to all repositories
      permissions: {
        contents: 'read',
        metadata: 'read',
        pull_requests: 'write',
        issues: 'write',
        actions: 'read'
      }
    }, {
      headers: {
        'Authorization': `Bearer ${jwt}`,
        'Accept': 'application/vnd.github.v3+json'
      }
    });

    return {
      token: response.data.token,
      expires_at: response.data.expires_at
    };
  } catch (error) {
    if (error.response) {
      const status = error.response.status;
      const message = error.response.data?.message || 'Unknown error';
      
      if (status === 401) {
        throw new Error(`Authentication failed: Invalid JWT or App credentials. ${message}`);
      } else if (status === 404) {
        throw new Error(`Installation not found: App may not be installed for organization '${organization}' or installation ID '${installationId}' is incorrect. ${message}`);
      } else if (status === 422) {
        throw new Error(`Invalid request: ${message}`);
      } else {
        throw new Error(`GitHub API error (${status}): ${message}`);
      }
    } else if (error.code === 'ECONNREFUSED') {
      throw new Error('Connection refused: Check your network connectivity and proxy settings');
    } else if (error.code === 'ETIMEDOUT') {
      throw new Error('Request timeout: GitHub API request timed out');
    } else {
      throw new Error(`Network error: ${error.message}`);
    }
  }
}

/**
 * Validate private key format
 */
function validatePrivateKey(privateKey) {
  if (!privateKey.includes('BEGIN RSA PRIVATE KEY') && !privateKey.includes('BEGIN PRIVATE KEY')) {
    throw new Error('Invalid private key format. Expected PEM format with proper headers.');
  }
  
  if (privateKey.includes('\\n')) {
    core.warning('Private key contains literal \\n characters. Converting to actual newlines.');
    return privateKey.replace(/\\n/g, '\n');
  }
  
  return privateKey;
}

/**
 * Extract App ID from JWT payload (for logging purposes)
 */
function extractAppIdFromKey(privateKey) {
  // This is a simplified extraction - in practice, you might want to
  // pass the App ID as a separate input for better security
  return process.env.GITHUB_APP_ID || 'unknown';
}

async function run() {
  try {
    core.info('Starting GitHub App token generation...');
    
    // Get inputs
    const organization = core.getInput('github_organization', { required: true });
    const installationId = core.getInput('app_installation_id', { required: true });
    const privateKey = core.getInput('app_private_key', { required: true });
    const proxyUrl = core.getInput('proxy_url');
    const proxyUsername = core.getInput('proxy_username');
    const proxyPassword = core.getInput('proxy_password');
    const tokenExpiration = parseInt(core.getInput('token_expiration') || '60');

    // Validate inputs
    if (!organization.trim()) {
      throw new Error('GitHub organization name cannot be empty');
    }
    
    if (!installationId.trim() || isNaN(parseInt(installationId))) {
      throw new Error('App installation ID must be a valid number');
    }
    
    if (tokenExpiration < 1 || tokenExpiration > 60) {
      throw new Error('Token expiration must be between 1 and 60 minutes');
    }

    // Validate and clean private key
    const cleanPrivateKey = validatePrivateKey(privateKey.trim());
    
    // Extract App ID (you should pass this as a separate input in production)
    const appId = process.env.GITHUB_APP_ID;
    if (!appId) {
      throw new Error('GITHUB_APP_ID environment variable is required');
    }

    core.info(`Generating token for organization: ${organization}`);
    core.info(`Using installation ID: ${installationId}`);
    core.info(`Token expiration: ${tokenExpiration} minutes`);
    
    if (proxyUrl) {
      core.info(`Using proxy: ${proxyUrl}`);
    }

    // Generate JWT
    const jwt = generateJWT(appId, cleanPrivateKey);
    core.info('JWT generated successfully');

    // Create HTTP client with proxy support
    const httpClient = createHttpClient(proxyUrl, proxyUsername, proxyPassword);

    // Get installation access token
    const tokenData = await getInstallationToken(httpClient, jwt, installationId, organization);
    
    core.info('Installation access token generated successfully');
    core.info(`Token expires at: ${tokenData.expires_at}`);

    // Set outputs (mask the token for security)
    core.setSecret(tokenData.token);
    core.setOutput('token', tokenData.token);
    core.setOutput('expires_at', tokenData.expires_at);

    core.info('✅ GitHub App token generation completed successfully');
    
  } catch (error) {
    core.error(`❌ Failed to generate GitHub App token: ${error.message}`);
    core.setFailed(error.message);
  }
}

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  core.error(`Unhandled promise rejection: ${reason}`);
  core.setFailed(`Unhandled promise rejection: ${reason}`);
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  core.error(`Uncaught exception: ${error.message}`);
  core.setFailed(`Uncaught exception: ${error.message}`);
});

if (require.main === module) {
  run();
}

module.exports = { run };
