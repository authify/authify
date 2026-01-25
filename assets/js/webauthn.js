/**
 * WebAuthn/FIDO2 Utilities
 *
 * Provides common functions for WebAuthn credential registration and authentication.
 */

// Base64URL encoding/decoding helpers
export function base64urlDecode(base64url) {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const padding = '='.repeat((4 - base64.length % 4) % 4);
  const binary = atob(base64 + padding);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

export function base64urlEncode(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Check if WebAuthn is supported in the current browser
 */
export function isWebAuthnSupported() {
  return !!window.PublicKeyCredential;
}

/**
 * WebAuthn Registration Handler
 */
export class WebAuthnRegistration {
  constructor(options) {
    this.beginUrl = options.beginUrl;
    this.completeUrl = options.completeUrl;
    this.redirectUrl = options.redirectUrl;
    this.csrfToken = options.csrfToken;
  }

  async register(authenticatorType, credentialName) {
    const authenticatorAttachment = authenticatorType === 'any' ? null : authenticatorType;
    const credentialType = authenticatorType === 'platform' ? 'platform' : 'roaming';

    // Step 1: Get registration options from server
    const beginResponse = await fetch(this.beginUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': this.csrfToken
      },
      body: JSON.stringify({
        authenticatorAttachment: authenticatorAttachment,
        credentialType: credentialType
      })
    });

    const beginData = await beginResponse.json();
    if (!beginData.success) {
      throw new Error(beginData.error || 'Failed to start registration');
    }

    // Step 2: Convert options for WebAuthn API
    const publicKeyOptions = beginData.options;
    publicKeyOptions.challenge = base64urlDecode(publicKeyOptions.challenge);
    publicKeyOptions.user.id = base64urlDecode(publicKeyOptions.user.id);

    // Decode excludeCredentials IDs from base64url to ArrayBuffer
    if (publicKeyOptions.excludeCredentials) {
      publicKeyOptions.excludeCredentials = publicKeyOptions.excludeCredentials.map(cred => ({
        ...cred,
        id: base64urlDecode(cred.id)
      }));
    }

    // Step 3: Create credential
    const credential = await navigator.credentials.create({
      publicKey: publicKeyOptions
    });

    // Step 4: Send credential to server
    const completeResponse = await fetch(this.completeUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': this.csrfToken
      },
      body: JSON.stringify({
        credentialName: credentialName,
        credentialType: credentialType,
        attestationResponse: {
          id: credential.id,
          rawId: base64urlEncode(credential.rawId),
          type: credential.type,
          response: {
            clientDataJSON: base64urlEncode(credential.response.clientDataJSON),
            attestationObject: base64urlEncode(credential.response.attestationObject),
            transports: credential.response.getTransports ? credential.response.getTransports() : []
          }
        }
      })
    });

    const completeData = await completeResponse.json();
    if (!completeData.success) {
      throw new Error(completeData.error || 'Failed to complete registration');
    }

    return completeData;
  }
}

/**
 * WebAuthn Authentication Handler
 */
export class WebAuthnAuthentication {
  constructor(options) {
    this.beginUrl = options.beginUrl;
    this.completeUrl = options.completeUrl;
    this.csrfToken = options.csrfToken;
  }

  async authenticate(rememberDevice = false) {
    // Step 1: Get authentication options from server
    const beginResponse = await fetch(this.beginUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': this.csrfToken
      }
    });

    const beginData = await beginResponse.json();
    if (!beginData.success) {
      throw new Error(beginData.error || 'Failed to start authentication');
    }

    // Step 2: Convert options for WebAuthn API
    const publicKeyOptions = beginData.options;
    publicKeyOptions.challenge = base64urlDecode(publicKeyOptions.challenge);
    publicKeyOptions.allowCredentials = publicKeyOptions.allowCredentials.map(cred => ({
      ...cred,
      id: base64urlDecode(cred.id)
    }));

    // Step 3: Get credential
    const assertion = await navigator.credentials.get({
      publicKey: publicKeyOptions
    });

    // Step 4: Send assertion to server
    const completeResponse = await fetch(this.completeUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': this.csrfToken
      },
      body: JSON.stringify({
        rememberDevice: rememberDevice,
        assertionResponse: {
          id: assertion.id,
          rawId: base64urlEncode(assertion.rawId),
          type: assertion.type,
          response: {
            clientDataJSON: base64urlEncode(assertion.response.clientDataJSON),
            authenticatorData: base64urlEncode(assertion.response.authenticatorData),
            signature: base64urlEncode(assertion.response.signature),
            userHandle: assertion.response.userHandle ? base64urlEncode(assertion.response.userHandle) : null
          }
        }
      })
    });

    const completeData = await completeResponse.json();
    if (!completeData.success) {
      throw new Error(completeData.error || 'Authentication failed');
    }

    return completeData;
  }
}

/**
 * Format WebAuthn errors for user-friendly display
 */
export function formatWebAuthnError(error) {
  if (error.name === 'NotAllowedError') {
    return 'Operation was cancelled or timed out.';
  } else if (error.name === 'InvalidStateError') {
    return 'This security key is already registered.';
  } else if (error.name === 'NotSupportedError') {
    return 'WebAuthn is not supported in this browser.';
  } else if (error.name === 'SecurityError') {
    return 'Security requirements not met.';
  } else {
    return error.message || 'An error occurred. Please try again.';
  }
}
