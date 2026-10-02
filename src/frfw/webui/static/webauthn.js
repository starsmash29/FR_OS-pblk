// Security keys / passkeys for the webUI (security-lessons G5).
// The server speaks py_webauthn's JSON (base64url strings); the browser
// API wants ArrayBuffers -- this file only converts between the two.
"use strict";

(function () {
  function toBuffer(b64url) {
    const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
    const bin = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
    return Uint8Array.from(bin, (c) => c.charCodeAt(0)).buffer;
  }

  function toB64url(buffer) {
    let bin = "";
    new Uint8Array(buffer).forEach((b) => { bin += String.fromCharCode(b); });
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function descriptors(list) {
    return (list || []).map((c) => Object.assign({}, c, { id: toBuffer(c.id) }));
  }

  async function postJSON(url, body) {
    const csrfMeta = document.querySelector('meta[name="csrf-token"]');
    const csrfToken = csrfMeta ? csrfMeta.getAttribute("content") : "";
    const headers = { "Content-Type": "application/json" };
    if (csrfToken) {
      headers["X-CSRF-Token"] = csrfToken;
    }
    const response = await fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: headers,
      body: JSON.stringify(body || {}),
    });
    let data = {};
    try { data = await response.json(); } catch (e) { /* not JSON */ }
    if (!response.ok) throw new Error(data.error || ("HTTP " + response.status));
    return data;
  }

  function show(el, message) {
    if (!el) return;
    el.textContent = message;
    el.hidden = !message;
  }

  // Sign-in: /login/mfa
  async function signIn(errorEl) {
    show(errorEl, "");
    try {
      const options = await postJSON("/login/mfa/webauthn/options");
      options.challenge = toBuffer(options.challenge);
      options.allowCredentials = descriptors(options.allowCredentials);
      const credential = await navigator.credentials.get({ publicKey: options });
      const r = credential.response;
      const result = await postJSON("/login/mfa/webauthn/verify", {
        id: credential.id,
        rawId: toB64url(credential.rawId),
        type: credential.type,
        response: {
          clientDataJSON: toB64url(r.clientDataJSON),
          authenticatorData: toB64url(r.authenticatorData),
          signature: toB64url(r.signature),
          userHandle: r.userHandle ? toB64url(r.userHandle) : null,
        },
        clientExtensionResults: credential.getClientExtensionResults(),
      });
      window.location.assign(result.redirect || "/");
    } catch (e) {
      show(errorEl, e.message || String(e));
    }
  }

  // Enrolment: /account/mfa
  async function register(form, errorEl) {
    show(errorEl, "");
    try {
      const start = await postJSON("/account/mfa/webauthn/options", {
        password: form.elements.password.value,
        name: form.elements.name.value,
      });
      const options = start.options;
      options.challenge = toBuffer(options.challenge);
      options.user.id = toBuffer(options.user.id);
      options.excludeCredentials = descriptors(options.excludeCredentials);
      const credential = await navigator.credentials.create({ publicKey: options });
      const r = credential.response;
      const result = await postJSON("/account/mfa/webauthn/register", {
        tid: start.tid,
        credential: {
          id: credential.id,
          rawId: toB64url(credential.rawId),
          type: credential.type,
          response: {
            clientDataJSON: toB64url(r.clientDataJSON),
            attestationObject: toB64url(r.attestationObject),
            transports: r.getTransports ? r.getTransports() : [],
          },
          clientExtensionResults: credential.getClientExtensionResults(),
        },
      });
      window.location.assign(result.redirect || "/account/mfa");
    } catch (e) {
      show(errorEl, e.message || String(e));
    }
  }

  document.addEventListener("DOMContentLoaded", function () {
    const supported = !!(window.PublicKeyCredential && navigator.credentials);
    const signInButton = document.getElementById("webauthn-signin");
    if (signInButton) {
      const errorEl = document.getElementById("webauthn-error");
      if (!supported) { signInButton.disabled = true; show(errorEl, "This browser has no security-key support."); }
      signInButton.addEventListener("click", function () { signIn(errorEl); });
    }
    const registerForm = document.getElementById("webauthn-register");
    if (registerForm) {
      const errorEl = document.getElementById("webauthn-error");
      if (!supported) { show(errorEl, "This browser has no security-key support."); }
      registerForm.addEventListener("submit", function (event) {
        event.preventDefault();
        register(registerForm, errorEl);
      });
    }
  });
})();
