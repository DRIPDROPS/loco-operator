# OAuth and OIDC in Electron Apps: Google and Microsoft Integration

## Introduction and Objectives
OAuth 2.0 and OpenID Connect (OIDC) are the industry standards for secure authentication and authorization in modern applications, including desktop apps built with Electron. Integrating Google and Microsoft sign-in into an Electron app presents unique challenges, especially around handling redirect URIs, complying with provider security policies, and ensuring a seamless user experience. This report provides a comprehensive, up-to-date guide for implementing OAuth and OIDC in Electron apps, with a focus on Google and Microsoft providers. It addresses common issues such as `redirect_uri_mismatch`, explains best practices for local development and production, and provides actionable examples and troubleshooting tips for developers.

## OAuth and OIDC Overview for Desktop/Electron Apps
OAuth 2.0 and OIDC are widely used to delegate authentication and authorization to trusted identity providers, allowing users to sign in with their existing accounts. For desktop applications like those built with Electron, the recommended approach is to use the Authorization Code flow with Proof Key for Code Exchange (PKCE), leveraging the system browser or a secure popup window to complete the authentication process. Both Google and Microsoft have strict security policies that restrict the use of embedded webviews and require specific redirect URI formats, such as custom URI schemes or loopback addresses. This report outlines the technical requirements, security considerations, and implementation patterns for integrating OAuth/OIDC in Electron, ensuring compliance with provider policies and a smooth user experience.

## Google OAuth/OIDC in Electron
### Overview
Integrating Google OAuth/OIDC into an Electron app requires careful attention to Google's security policies, especially regarding redirect URIs and the use of embedded browsers. Google explicitly prohibits the use of embedded webviews (such as Electron's `<webview>` or `<iframe>`) for OAuth authentication flows due to security concerns [[Google OAuth Embedded Webview Policy](https://developers.googleblog.com/2016/08/modernizing-oauth-interactions-in-native-apps.html)]. Instead, you must use the system browser or a secure popup window.

### Recommended Flow
1. **Use the Authorization Code Flow with PKCE**: This is the recommended and most secure OAuth flow for desktop apps, including Electron [[Google OAuth 2.0 for Native Apps](https://developers.google.com/identity/protocols/oauth2/native-app)].
2. **Open the System Browser or a Secure Popup**: Launch the OAuth consent screen in the user's default browser (preferred) or a secure Electron `BrowserWindow` (not `<webview>` or `<iframe>`).
3. **Handle the Redirect URI**: Use a custom URI scheme (e.g., `myapp://auth`) or a loopback address (e.g., `http://127.0.0.1:PORT/callback`) as the redirect URI.
   - **Custom URI Scheme**: Register your app to handle a custom protocol and configure this as the redirect URI in the Google Cloud Console.
   - **Loopback Address**: Start a local HTTP server in your Electron app to listen for the OAuth callback.
4. **Exchange the Authorization Code for Tokens**: After receiving the authorization code at your redirect URI, exchange it for access and ID tokens using Google's token endpoint.

### Registering Redirect URIs in Google Cloud Console
- **For Custom URI Scheme**: Register a redirect URI like `com.example.myapp:/oauth2redirect` in the Google Cloud Console under your OAuth 2.0 client credentials.
- **For Loopback Address**: Register URIs like `http://127.0.0.1:PORT/callback` (Google allows any available port).

**Note:** Do not use `file://` or `localhost` as the redirect URI for production apps. Google recommends loopback or custom schemes for desktop apps [[Google OAuth 2.0 for Native Apps](https://developers.google.com/identity/protocols/oauth2/native-app)].

### Example: Using Loopback Redirect URI in Electron
```js
const { app, BrowserWindow } = require('electron');
const http = require('http');
const open = require('open');

function startOAuth() {
  const port = 42813; // Use a random available port
  const redirectUri = `http://127.0.0.1:${port}/callback`;
  const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?client_id=YOUR_CLIENT_ID&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=openid%20email%20profile&code_challenge=YOUR_CODE_CHALLENGE&code_challenge_method=S256`;

  // Start a local server to receive the OAuth callback
  const server = http.createServer((req, res) => {
    if (req.url.startsWith('/callback')) {
      // Parse the code from the URL and close the server
      const urlObj = new URL(req.url, `http://127.0.0.1:${port}`);
      const code = urlObj.searchParams.get('code');
      res.end('Authentication successful! You can close this window.');
      server.close();
      // Exchange the code for tokens...
    }
  });
  server.listen(port, () => {
    // Open the system browser to the Google OAuth URL
    open(authUrl);
  });
}
```

### Example: Using Custom URI Scheme
1. Register a custom protocol in Electron:
   ```js
   app.setAsDefaultProtocolClient('myapp');
   ```
2. Register `myapp://auth` as a redirect URI in Google Cloud Console.
3. In your OAuth flow, use `myapp://auth` as the redirect URI.
4. Handle the protocol in your Electron app to receive the authorization code.

### Libraries and Tools
- [google-auth-library](https://www.npmjs.com/package/google-auth-library)
- [electron-oauth2](https://github.com/mawie81/electron-oauth2)
- [electron-oauth-helper](https://github.com/mironal/electron-oauth-helper)

### References
- [Google OAuth 2.0 for Native Apps](https://developers.google.com/identity/protocols/oauth2/native-app)
- [Modernizing OAuth Interactions in Native Apps](https://developers.googleblog.com/2016/08/modernizing-oauth-interactions-in-native-apps.html)
- [Electron Custom Protocol with OAuth Redirect - Stack Overflow](https://stackoverflow.com/questions/61926984/electron-custom-protocol-with-oauth-redirect)
- [How to authenticate with Google Oauth in Electron - DEV.to](https://dev.to/pragli/how-to-authenticate-with-google-oauth-in-electron-5218)

## Microsoft OAuth/OIDC in Electron
### Overview
Integrating Microsoft OAuth/OIDC (Azure AD, Microsoft Entra ID) into an Electron app requires careful attention to Microsoft's security policies and redirect URI requirements. Microsoft recommends using the Authorization Code flow with PKCE for desktop apps, and explicitly supports both custom URI schemes and loopback addresses for redirect URIs [[Microsoft Identity Platform: Desktop App Registration](https://learn.microsoft.com/en-us/entra/identity-platform/scenario-desktop-app-registration)]. Like Google, Microsoft does not allow the use of `file://` URIs or embedded webviews for OAuth flows in production.

### Recommended Flow
1. **Use the Authorization Code Flow with PKCE**: This is the recommended and most secure OAuth flow for desktop apps, including Electron [[Microsoft Identity Platform OAuth 2.0 Auth Code Flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow)].
2. **Open the System Browser or a Secure Popup**: Launch the OAuth consent screen in the user's default browser (preferred) or a secure Electron `BrowserWindow` (not `<webview>` or `<iframe>`).
3. **Handle the Redirect URI**: Use a custom URI scheme (e.g., `myapp://auth`) or a loopback address (e.g., `http://localhost:PORT`) as the redirect URI.
   - **Custom URI Scheme**: Register your app to handle a custom protocol and configure this as the redirect URI in the Azure portal.
   - **Loopback Address**: Start a local HTTP server in your Electron app to listen for the OAuth callback.
4. **Exchange the Authorization Code for Tokens**: After receiving the authorization code at your redirect URI, exchange it for access and ID tokens using Microsoft's token endpoint.

### Registering Redirect URIs in Azure Portal
- **For Custom URI Scheme**: Register a redirect URI like `msal{YOUR_CLIENT_ID}://auth` or `myapp://auth` as a "Mobile & desktop applications" redirect URI in the Azure portal.
- **For Loopback Address**: Register URIs like `http://localhost:PORT` (Microsoft allows any available port for loopback).

**Note:** Do not use `file://` as the redirect URI. Microsoft recommends loopback or custom schemes for desktop apps [[Redirect URI Best Practices](https://learn.microsoft.com/en-us/entra/identity-platform/reply-url)].

### Example: Using Loopback Redirect URI in Electron with MSAL Node
Microsoft provides the [MSAL Node library](https://www.npmjs.com/package/@azure/msal-node) with Electron samples:

```js
const { app, BrowserWindow } = require('electron');
const http = require('http');
const open = require('open');
const msal = require('@azure/msal-node');

function startMicrosoftOAuth() {
  const port = 42814; // Use a random available port
  const redirectUri = `http://localhost:${port}`;
  const msalConfig = {
    auth: {
      clientId: 'YOUR_CLIENT_ID',
      authority: 'https://login.microsoftonline.com/common',
      redirectUri: redirectUri,
    },
    system: { loggerOptions: { loggerCallback: () => {} } }
  };
  const pca = new msal.PublicClientApplication(msalConfig);

  // Start a local server to receive the OAuth callback
  const server = http.createServer((req, res) => {
    if (req.url.startsWith('/')) {
      const urlObj = new URL(req.url, `http://localhost:${port}`);
      const code = urlObj.searchParams.get('code');
      res.end('Authentication successful! You can close this window.');
      server.close();
      // Exchange the code for tokens...
    }
  });
  server.listen(port, () => {
    // Build the auth code URL and open the system browser
    pca.getAuthCodeUrl({
      scopes: ['openid', 'profile', 'email'],
      redirectUri: redirectUri,
      codeChallenge: 'YOUR_CODE_CHALLENGE',
      codeChallengeMethod: 'S256',
    }).then((authUrl) => {
      open(authUrl);
    });
  });
}
```

### Example: Using Custom URI Scheme
1. Register a custom protocol in Electron:
   ```js
   app.setAsDefaultProtocolClient('myapp');
   ```
2. Register `myapp://auth` or `msal{YOUR_CLIENT_ID}://auth` as a redirect URI in Azure portal.
3. In your OAuth flow, use this custom URI as the redirect URI.
4. Handle the protocol in your Electron app to receive the authorization code.

### Libraries and Tools
- [@azure/msal-node](https://www.npmjs.com/package/@azure/msal-node)
- [electron-oauth2](https://github.com/mawie81/electron-oauth2)
- [electron-oauth-helper](https://github.com/mironal/electron-oauth-helper)

### References
- [Register desktop apps that call web APIs - Microsoft identity platform](https://learn.microsoft.com/en-us/entra/identity-platform/scenario-desktop-app-registration)
- [Redirect URI (reply URL) best practices and limitations - Microsoft](https://learn.microsoft.com/en-us/entra/identity-platform/reply-url)
- [MSAL Node Electron Sample Using System browser and Custom URL Scheme](https://github.com/AzureAD/microsoft-authentication-library-for-js/blob/dev/samples/msal-node-samples/ElectronSystemBrowserTestApp/README.md)
- [Tutorial: Sign in users and call the Microsoft Graph API in an Electron desktop app](https://learn.microsoft.com/en-us/entra/identity-platform/tutorial-v2-nodejs-desktop)

## Handling Redirect URIs and redirect_uri_mismatch Errors
### Overview
Handling redirect URIs is one of the most common challenges when implementing OAuth/OIDC in Electron apps, especially for local development. Both Google and Microsoft enforce strict rules on which redirect URIs are allowed, and mismatches between the registered and actual redirect URIs will result in errors such as `redirect_uri_mismatch`.

### Common Causes of redirect_uri_mismatch
- The redirect URI in your OAuth request does not exactly match one of the URIs registered in the provider's developer console.
- Using `localhost` instead of `127.0.0.1`, or vice versa, when the registered URI is different.
- Using a port number that is not registered (for providers that require fixed ports).
- Using `file://` or embedded webviews, which are not allowed by Google or Microsoft.
- Typographical errors or missing trailing slashes in the registered URI.

### Best Practices for Registering Redirect URIs
#### Google
- **Loopback URIs:** Register `http://127.0.0.1:PORT/callback` (Google allows any port; you do not need to register every possible port, just the pattern).
- **Custom URI Schemes:** Register a URI like `com.example.myapp:/oauth2redirect`.
- **Do not use:** `file://` or embedded webviews.
- **Reference:** [Google OAuth 2.0 for Native Apps](https://developers.google.com/identity/protocols/oauth2/native-app)

#### Microsoft
- **Loopback URIs:** Register `http://localhost:PORT` (Microsoft allows any port for loopback).
- **Custom URI Schemes:** Register a URI like `msal{YOUR_CLIENT_ID}://auth` or `myapp://auth` as a "Mobile & desktop applications" redirect URI.
- **Do not use:** `file://` or embedded webviews.
- **Reference:** [Redirect URI (reply URL) best practices and limitations - Microsoft](https://learn.microsoft.com/en-us/entra/identity-platform/reply-url)

### Troubleshooting redirect_uri_mismatch
1. **Check for Exact Match:** The redirect URI in your OAuth request must exactly match one of the URIs registered in the provider's developer console (case-sensitive, no extra slashes).
2. **Use Loopback or Custom Schemes:** For local development, use a loopback address (with a random port) or a custom URI scheme. Avoid `file://` and embedded webviews.
3. **Update Provider Console:** If you change your redirect URI in code, update the registered URI in the provider's developer console.
4. **Check for Embedded Webview Restrictions:** Google and Microsoft both block OAuth in embedded webviews for security reasons. Use the system browser or a secure popup.
5. **Review Error Messages:** Provider error messages often specify the expected and actual redirect URIs. Use this information to correct mismatches.

### Example Error and Solution
**Error:**  
```
Error 400: redirect_uri_mismatch
You can't sign in to this app because it doesn't comply with Google's OAuth 2.0 policy.
If you're the app developer, register the JavaScript origin in the Google Cloud Console.
Request details: origin=http://localhost:6006 flowName=GeneralOAuthFlow
```
**Solution:**  
- Register `http://localhost:6006` (or the actual port you are using) as an authorized redirect URI in the Google Cloud Console.
- If using a random port, register the pattern or use a custom URI scheme.
- Ensure you are not using an embedded webview for the OAuth flow.

### References
- [Google OAuth 2.0 for Native Apps](https://developers.google.com/identity/protocols/oauth2/native-app)
- [Redirect URI (reply URL) best practices and limitations - Microsoft](https://learn.microsoft.com/en-us/entra/identity-platform/reply-url)
- [Handling oauth2 redirect from electron (or other desktop platforms) - Stack Overflow](https://stackoverflow.com/questions/37546656/handling-oauth2-redirect-from-electron-or-other-desktop-platforms)
- [Electron redirect URI scheme best practices - GitHub](https://github.com/AzureAD/microsoft-authentication-library-for-js/issues/6798)

## Security and UX Best Practices
### Security Best Practices
- **Use Authorization Code Flow with PKCE:** Always use the Authorization Code flow with PKCE for desktop/Electron apps to prevent interception attacks [[RFC 8252](https://datatracker.ietf.org/doc/html/rfc8252)].
- **Avoid Embedded Webviews:** Never use embedded webviews (`<webview>`, `<iframe>`) for OAuth flows. Both Google and Microsoft block these for security reasons [[Google OAuth Embedded Webview Policy](https://developers.googleblog.com/2016/08/modernizing-oauth-interactions-in-native-apps.html)].
- **Use System Browser or Secure Popup:** Prefer launching the system browser for authentication. If using an Electron `BrowserWindow`, ensure it is isolated, has no node integration, and disables features like `webSecurity: false`.
- **Validate Redirect URIs:** Only accept OAuth callbacks on registered, trusted redirect URIs. Never process codes from untrusted sources.
- **Store Tokens Securely:** Store access and refresh tokens in memory or encrypted storage. Avoid localStorage, sessionStorage, or unencrypted disk storage.
- **Limit Token Scope and Lifetime:** Request only the scopes you need and use short-lived tokens where possible.
- **Implement CSRF Protection:** Use state parameters and validate them on callback to prevent CSRF attacks.
- **Monitor and Log Authentication Events:** Track login attempts, errors, and suspicious activity for auditing and incident response.

### UX Best Practices
- **Clear Sign-In Buttons:** Use branded, accessible buttons for Google and Microsoft sign-in.
- **Progress and Error Feedback:** Show loading indicators during authentication and provide clear, actionable error messages on failure.
- **Seamless Browser/App Handoff:** When using the system browser, provide instructions or deep links to return to the Electron app after authentication.
- **Session Management:** Clearly indicate when a session has expired and prompt the user to re-authenticate.
- **Accessibility:** Ensure all authentication UI elements are accessible via keyboard and screen readers.
- **Privacy Transparency:** Clearly communicate what data will be accessed and how it will be used.
- **Allow Account Switching:** Let users easily sign out and sign in with a different account.

### References
- [OAuth 2.0 for Native Apps (RFC 8252)](https://datatracker.ietf.org/doc/html/rfc8252)
- [Modernizing OAuth Interactions in Native Apps (Google)](https://developers.googleblog.com/2016/08/modernizing-oauth-interactions-in-native-apps.html)
- [Microsoft Identity Platform Security Best Practices](https://learn.microsoft.com/en-us/azure/active-directory/develop/security-best-practices)
- [OWASP OAuth Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth_Cheat_Sheet.html)

## Example Code and Implementation Patterns
### Example: Google OAuth with Loopback Redirect (Node.js/Electron)
```js
const { app } = require('electron');
const http = require('http');
const open = require('open');
const crypto = require('crypto');

function generateCodeVerifier() {
  return crypto.randomBytes(32).toString('base64url');
}

function generateCodeChallenge(verifier) {
  return crypto.createHash('sha256').update(verifier).digest('base64url');
}

function startGoogleOAuth() {
  const port = 42813;
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);
  const redirectUri = `http://127.0.0.1:${port}/callback`;
  const clientId = 'YOUR_CLIENT_ID';
  const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=openid%20email%20profile&code_challenge=${codeChallenge}&code_challenge_method=S256`;

  const server = http.createServer((req, res) => {
    if (req.url.startsWith('/callback')) {
      const urlObj = new URL(req.url, `http://127.0.0.1:${port}`);
      const code = urlObj.searchParams.get('code');
      res.end('Authentication successful! You can close this window.');
      server.close();
      // Exchange the code for tokens using codeVerifier...
    }
  });
  server.listen(port, () => {
    open(authUrl);
  });
}
```

### Example: Microsoft OAuth with MSAL Node and Loopback Redirect
```js
const { app } = require('electron');
const http = require('http');
const open = require('open');
const msal = require('@azure/msal-node');

function startMicrosoftOAuth() {
  const port = 42814;
  const redirectUri = `http://localhost:${port}`;
  const msalConfig = {
    auth: {
      clientId: 'YOUR_CLIENT_ID',
      authority: 'https://login.microsoftonline.com/common',
      redirectUri: redirectUri,
    },
    system: { loggerOptions: { loggerCallback: () => {} } }
  };
  const pca = new msal.PublicClientApplication(msalConfig);

  const server = http.createServer((req, res) => {
    if (req.url.startsWith('/')) {
      const urlObj = new URL(req.url, `http://localhost:${port}`);
      const code = urlObj.searchParams.get('code');
      res.end('Authentication successful! You can close this window.');
      server.close();
      // Exchange the code for tokens...
    }
  });
  server.listen(port, () => {
    pca.getAuthCodeUrl({
      scopes: ['openid', 'profile', 'email'],
      redirectUri: redirectUri,
      codeChallenge: 'YOUR_CODE_CHALLENGE',
      codeChallengeMethod: 'S256',
    }).then((authUrl) => {
      open(authUrl);
    });
  });
}
```

### Example: Registering a Custom Protocol in Electron
```js
// In your Electron main process
app.setAsDefaultProtocolClient('myapp');
// Register 'myapp://auth' as a redirect URI in your provider's console.
```

### Example: Using electron-oauth2 Library
```js
const { oauth2 } = require('electron-oauth2');
const config = {
  clientId: 'YOUR_CLIENT_ID',
  clientSecret: 'YOUR_CLIENT_SECRET',
  authorizationUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
  tokenUrl: 'https://oauth2.googleapis.com/token',
  useBasicAuthorizationHeader: false,
  redirectUri: 'http://127.0.0.1:42813/callback'
};
const windowParams = {
  alwaysOnTop: true,
  autoHideMenuBar: true,
  webPreferences: { nodeIntegration: false }
};
oauth2(config, windowParams)
  .getAccessToken({})
  .then(token => {
    // Use the token
  });
```

### References
- [electron-oauth2 GitHub](https://github.com/mawie81/electron-oauth2)
- [MSAL Node Electron Sample](https://github.com/AzureAD/microsoft-authentication-library-for-js/blob/dev/samples/msal-node-samples/ElectronSystemBrowserTestApp/README.md)
- [Google OAuth 2.0 for Native Apps](https://developers.google.com/identity/protocols/oauth2/native-app)

## Troubleshooting and Common Pitfalls
### Common Pitfalls and Troubleshooting
#### 1. redirect_uri_mismatch Errors
- **Symptom:** Authentication fails with an error indicating the redirect URI doesn't match.
- **Troubleshooting:** Ensure the URI in your code exactly matches the one registered in the provider's console. For Google, use `http://127.0.0.1:PORT`; for Microsoft, use `http://localhost:PORT`. Double-check for typos, case sensitivity, and trailing slashes.
- **Prevention:** Always test URIs in a development environment first and update registrations as needed.

#### 2. Embedded Webview Issues
- **Symptom:** OAuth flows are blocked or flagged as insecure.
- **Troubleshooting:** Switch to the system browser or a secure `BrowserWindow`. Check provider logs for specific policy violations.
- **Prevention:** Follow provider guidelines by avoiding `<webview>` or `<iframe>` for authentication.

#### 3. Token Storage and Expiration Problems
- **Symptom:** Sessions expire unexpectedly or tokens are invalid.
- **Troubleshooting:** Verify token lifetimes and implement refresh token logic. Use secure storage like keychain or encrypted files.
- **Prevention:** Limit scopes and use short-lived tokens; test expiration handling in your app.

#### 4. CSRF and State Parameter Failures
- **Symptom:** Authentication callbacks are rejected due to state mismatches.
- **Troubleshooting:** Ensure the state parameter is generated securely and validated on callback. Regenerate and compare values.
- **Prevention:** Always include and verify the state parameter in OAuth requests.

#### 5. Network and CORS Issues
- **Symptom:** Requests fail due to CORS errors or network restrictions.
- **Troubleshooting:** Configure CORS in your server settings to allow the redirect URI. Test with tools like Postman.
- **Prevention:** Use loopback addresses and ensure your app handles cross-origin requests properly.

#### 6. Library-Specific Errors (e.g., MSAL or electron-oauth2)
- **Symptom:** Library errors like invalid configuration.
- **Troubleshooting:** Review library documentation for setup; ensure client ID, secret, and scopes are correct.
- **Prevention:** Use the latest library versions and test configurations in isolation.

### General Troubleshooting Steps
1. **Check Logs:** Use browser dev tools and app logs to capture error details.
2. **Test Incrementally:** Isolate authentication flows and test each part separately.
3. **Validate Environment:** Ensure dependencies are up-to-date and compatible.
4. **Consult Documentation:** Refer to provider-specific guides for the latest changes.

### References
- [Google OAuth Troubleshooting](https://developers.google.com/identity/protocols/oauth2/troubleshooting)
- [Microsoft Identity Platform Troubleshooting](https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes)
- [Electron Security Best Practices](https://www.electronjs.org/docs/latest/tutorial/security)

## Conclusion
[PLACEHOLDER_CONCLUSION]

## Bibliography
[PLACEHOLDER_BIBLIOGRAPHY]