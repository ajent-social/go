// humanauthPasskey drives the passkey ceremonies served under a humanauth
// prefix. login(prefix) signs in and follows the returned redirect;
// register(prefix, csrfToken) adds a passkey to the signed-in subject.
(function (global) {
  "use strict";

  function toBuffer(value) {
    var b64 = String(value).replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4) {
      b64 += "=";
    }
    var bin = atob(b64);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) {
      out[i] = bin.charCodeAt(i);
    }
    return out.buffer;
  }

  function toBase64URL(buf) {
    if (buf === null || buf === undefined) {
      return undefined;
    }
    var bytes = new Uint8Array(buf);
    var bin = "";
    for (var i = 0; i < bytes.length; i++) {
      bin += String.fromCharCode(bytes[i]);
    }
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function mapCredentialIDs(list) {
    return (list || []).map(function (c) {
      var copy = Object.assign({}, c);
      copy.id = toBuffer(c.id);
      return copy;
    });
  }

  function creationOptions(json) {
    var pk = json.publicKey;
    if (typeof PublicKeyCredential.parseCreationOptionsFromJSON === "function") {
      return PublicKeyCredential.parseCreationOptionsFromJSON(pk);
    }
    var opts = Object.assign({}, pk);
    opts.challenge = toBuffer(pk.challenge);
    opts.user = Object.assign({}, pk.user, { id: toBuffer(pk.user.id) });
    if (pk.excludeCredentials) {
      opts.excludeCredentials = mapCredentialIDs(pk.excludeCredentials);
    }
    return opts;
  }

  function requestOptions(json) {
    var pk = json.publicKey;
    if (typeof PublicKeyCredential.parseRequestOptionsFromJSON === "function") {
      return PublicKeyCredential.parseRequestOptionsFromJSON(pk);
    }
    var opts = Object.assign({}, pk);
    opts.challenge = toBuffer(pk.challenge);
    if (pk.allowCredentials) {
      opts.allowCredentials = mapCredentialIDs(pk.allowCredentials);
    }
    return opts;
  }

  function credentialJSON(cred) {
    if (typeof cred.toJSON === "function") {
      return cred.toJSON();
    }
    var r = cred.response;
    var response = { clientDataJSON: toBase64URL(r.clientDataJSON) };
    if (r.attestationObject) {
      response.attestationObject = toBase64URL(r.attestationObject);
      if (typeof r.getTransports === "function") {
        response.transports = r.getTransports();
      }
    } else {
      response.authenticatorData = toBase64URL(r.authenticatorData);
      response.signature = toBase64URL(r.signature);
      response.userHandle = toBase64URL(r.userHandle);
    }
    return {
      id: cred.id,
      rawId: toBase64URL(cred.rawId),
      type: cred.type,
      authenticatorAttachment: cred.authenticatorAttachment || undefined,
      clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
      response: response
    };
  }

  function post(url, body, csrfToken) {
    var headers = { "Content-Type": "application/json" };
    if (csrfToken) {
      headers["X-CSRF-Token"] = csrfToken;
    }
    return fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: headers,
      body: body === undefined ? "{}" : JSON.stringify(body)
    });
  }

  function readJSON(res) {
    return res.json().catch(function () {
      return {};
    });
  }

  async function login(prefix) {
    var begin = await post(prefix + "/passkey/login/begin");
    if (!begin.ok) {
      throw new Error("passkey sign-in failed");
    }
    var cred = await navigator.credentials.get({ publicKey: requestOptions(await begin.json()) });
    var finish = await post(prefix + "/passkey/login/finish", credentialJSON(cred));
    var body = await readJSON(finish);
    if (!finish.ok || typeof body.redirect !== "string") {
      throw new Error(body.error || "passkey sign-in failed");
    }
    location.assign(body.redirect);
    return body.redirect;
  }

  async function register(prefix, csrfToken) {
    var begin = await post(prefix + "/passkey/register/begin", undefined, csrfToken);
    if (!begin.ok) {
      throw new Error((await readJSON(begin)).error || "passkey registration failed");
    }
    var cred = await navigator.credentials.create({ publicKey: creationOptions(await begin.json()) });
    var finish = await post(prefix + "/passkey/register/finish", credentialJSON(cred), csrfToken);
    if (finish.status !== 204) {
      throw new Error((await readJSON(finish)).error || "passkey registration failed");
    }
    return true;
  }

  global.humanauthPasskey = { login: login, register: register };
})(window);
