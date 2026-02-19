// js/src/index.js

export function createTasks() {
  const keys = new Map(); // keyId -> CryptoKey
  const keypairs = new Map(); // keypairId -> { publicKey, privateKey }
  const signingKeypairs = new Map();
  let nextId = 0;

  function newId() {
    return String(nextId++);
  }

  function storeKey(key) {
    const id = newId();
    keys.set(id, key);
    return id;
  }

  function getKey(id) {
    const key = keys.get(id);
    if (!key) return { error: "INVALID_KEY:Key not found" };
    return key;
  }

  function storeKeypair(kp) {
    const id = newId();
    keypairs.set(id, kp);
    return id;
  }

  // --- Helpers ---

  function toBase64(uint8array) {
    return btoa(String.fromCharCode(...uint8array));
  }

  function fromBase64(base64) {
    return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
  }

  async function rawPublicKeyHash(publicKey) {
    const rawBytes = await crypto.subtle.exportKey("raw", publicKey);
    const hashBuffer = await crypto.subtle.digest("SHA-256", rawBytes);
    return Array.from(new Uint8Array(hashBuffer))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  return {
    // --- SHA-256 ---

    "webcrypto:sha256hex": async ({ data }) => {
      try {
        const bytes =
          typeof data === "string"
            ? new TextEncoder().encode(data)
            : new Uint8Array(data);
        const hashBuffer = await crypto.subtle.digest("SHA-256", bytes);
        return Array.from(new Uint8Array(hashBuffer))
          .map((b) => b.toString(16).padStart(2, "0"))
          .join("");
      } catch (e) {
        return { error: "HASHING_FAILED:" + e.message };
      }
    },

    // --- Symmetric (AES-256-GCM) ---

    "webcrypto:sym:generateKey": async () => {
      const key = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"],
      );
      return storeKey(key);
    },

    "webcrypto:sym:encrypt": async ({ keyId, data }) => {
      const key = getKey(keyId);
      if (key.error) return key;
      try {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const plaintext = new Uint8Array(data);
        const ciphertextBuffer = await crypto.subtle.encrypt(
          { name: "AES-GCM", iv },
          key,
          plaintext,
        );
        return {
          ciphertext: toBase64(new Uint8Array(ciphertextBuffer)),
          iv: toBase64(iv),
        };
      } catch (e) {
        return { error: "ENCRYPTION_FAILED:" + e.message };
      }
    },

    "webcrypto:sym:decrypt": async ({ keyId, ciphertext, iv }) => {
      const key = getKey(keyId);
      if (key.error) return key;
      try {
        const decrypted = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: fromBase64(iv) },
          key,
          fromBase64(ciphertext),
        );
        return Array.from(new Uint8Array(decrypted));
      } catch (e) {
        return { error: "DECRYPTION_FAILED:Invalid key or corrupted data" };
      }
    },

    "webcrypto:sym:encryptString": async ({ keyId, plaintext }) => {
      const key = getKey(keyId);
      if (key.error) return key;
      try {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const data = new TextEncoder().encode(plaintext);
        const ciphertextBuffer = await crypto.subtle.encrypt(
          { name: "AES-GCM", iv },
          key,
          data,
        );
        return {
          ciphertext: toBase64(new Uint8Array(ciphertextBuffer)),
          iv: toBase64(iv),
        };
      } catch (e) {
        return { error: "ENCRYPTION_FAILED:" + e.message };
      }
    },

    "webcrypto:sym:decryptString": async ({ keyId, ciphertext, iv }) => {
      const key = getKey(keyId);
      if (key.error) return key;
      try {
        const decrypted = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: fromBase64(iv) },
          key,
          fromBase64(ciphertext),
        );
        return new TextDecoder().decode(decrypted);
      } catch (e) {
        return { error: "DECRYPTION_FAILED:Invalid key or corrupted data" };
      }
    },

    "webcrypto:sym:encryptJson": async ({ keyId, json }) => {
      const key = getKey(keyId);
      if (key.error) return key;
      try {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const data = new TextEncoder().encode(JSON.stringify(json));
        const ciphertextBuffer = await crypto.subtle.encrypt(
          { name: "AES-GCM", iv },
          key,
          data,
        );
        return {
          ciphertext: toBase64(new Uint8Array(ciphertextBuffer)),
          iv: toBase64(iv),
        };
      } catch (e) {
        return { error: "ENCRYPTION_FAILED:" + e.message };
      }
    },

    "webcrypto:sym:decryptJson": async ({ keyId, ciphertext, iv }) => {
      const key = getKey(keyId);
      if (key.error) return key;
      try {
        const decrypted = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: fromBase64(iv) },
          key,
          fromBase64(ciphertext),
        );
        return JSON.parse(new TextDecoder().decode(decrypted));
      } catch (e) {
        return { error: "DECRYPTION_FAILED:Invalid key or corrupted data" };
      }
    },

    "webcrypto:sym:exportKey": async ({ keyId }) => {
      const key = getKey(keyId);
      if (key.error) return key;
      try {
        const exported = await crypto.subtle.exportKey("raw", key);
        return toBase64(new Uint8Array(exported));
      } catch (e) {
        return { error: "KEY_EXPORT_FAILED:" + e.message };
      }
    },

    "webcrypto:sym:importKey": async ({ base64 }) => {
      try {
        const keyData = fromBase64(base64);
        const key = await crypto.subtle.importKey(
          "raw",
          keyData,
          { name: "AES-GCM", length: 256 },
          true,
          ["encrypt", "decrypt"],
        );
        return storeKey(key);
      } catch (e) {
        return { error: "KEY_IMPORT_FAILED:" + e.message };
      }
    },

    // --- Key Pair (ECDH P-256) ---

    "webcrypto:kp:generate": async () => {
      const kp = await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        true,
        ["deriveKey"],
      );
      return storeKeypair(kp);
    },

    "webcrypto:kp:export": async ({ keypairId }) => {
      const kp = keypairs.get(keypairId);
      if (!kp) return { error: "INVALID_KEY:KeyPair not found" };
      try {
        const pubJwk = await crypto.subtle.exportKey("jwk", kp.publicKey);
        const privJwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
        const hash = await rawPublicKeyHash(kp.publicKey);
        return {
          publicKey: JSON.stringify(pubJwk),
          privateKey: JSON.stringify(privJwk),
          publicKeyHash: hash,
        };
      } catch (e) {
        return { error: "KEY_EXPORT_FAILED:" + e.message };
      }
    },

    "webcrypto:kp:import": async ({ publicKey, privateKey }) => {
      try {
        const pubKey = await crypto.subtle.importKey(
          "jwk",
          JSON.parse(publicKey),
          { name: "ECDH", namedCurve: "P-256" },
          true,
          [],
        );
        const privKey = await crypto.subtle.importKey(
          "jwk",
          JSON.parse(privateKey),
          { name: "ECDH", namedCurve: "P-256" },
          true,
          ["deriveKey"],
        );
        return storeKeypair({ publicKey: pubKey, privateKey: privKey });
      } catch (e) {
        return { error: "KEY_IMPORT_FAILED:" + e.message };
      }
    },

    "webcrypto:kp:publicKeyHash": async ({ keypairId }) => {
      const kp = keypairs.get(keypairId);
      if (!kp) return { error: "INVALID_KEY:KeyPair not found" };
      return await rawPublicKeyHash(kp.publicKey);
    },

    "webcrypto:kp:deriveSharedKey": async ({
      myKeypairId,
      otherPublicKeyJwk,
    }) => {
      const kp = keypairs.get(myKeypairId);
      if (!kp) return { error: "INVALID_KEY:KeyPair not found" };
      try {
        const otherPub = await crypto.subtle.importKey(
          "jwk",
          JSON.parse(otherPublicKeyJwk),
          { name: "ECDH", namedCurve: "P-256" },
          true,
          [],
        );
        const sharedKey = await crypto.subtle.deriveKey(
          { name: "ECDH", public: otherPub },
          kp.privateKey,
          { name: "AES-GCM", length: 256 },
          true,
          ["encrypt", "decrypt"],
        );
        return storeKey(sharedKey);
      } catch (e) {
        return { error: "KEY_DERIVATION_FAILED:" + e.message };
      }
    },

    "webcrypto:kp:importPublicKey": async ({ publicKeyJwk }) => {
      try {
        const pubKey = await crypto.subtle.importKey(
          "jwk",
          JSON.parse(publicKeyJwk),
          { name: "ECDH", namedCurve: "P-256" },
          true,
          [],
        );
        // Store as a keypair with only a public key (no private key)
        const id = newId();
        keypairs.set(id, { publicKey: pubKey, privateKey: null });
        return id;
      } catch (e) {
        return { error: "KEY_IMPORT_FAILED:" + e.message };
      }
    },

    // --- Signing (ECDSA P-256) ---

    "webcrypto:sig:generate": async () => {
      const kp = await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign", "verify"],
      );
      const id = newId();
      signingKeypairs.set(id, kp);
      return id;
    },

    "webcrypto:sig:export": async ({ sigKeypairId }) => {
      const kp = signingKeypairs.get(sigKeypairId);
      if (!kp) return { error: "INVALID_KEY:SigningKeyPair not found" };
      try {
        const pubJwk = await crypto.subtle.exportKey("jwk", kp.publicKey);
        const privJwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
        return {
          publicKey: JSON.stringify(pubJwk),
          privateKey: JSON.stringify(privJwk),
        };
      } catch (e) {
        return { error: "KEY_EXPORT_FAILED:" + e.message };
      }
    },

    "webcrypto:sig:import": async ({ publicKey, privateKey }) => {
      try {
        const pubKey = await crypto.subtle.importKey(
          "jwk",
          JSON.parse(publicKey),
          { name: "ECDSA", namedCurve: "P-256" },
          true,
          ["verify"],
        );
        const privKey = await crypto.subtle.importKey(
          "jwk",
          JSON.parse(privateKey),
          { name: "ECDSA", namedCurve: "P-256" },
          true,
          ["sign"],
        );
        const id = newId();
        signingKeypairs.set(id, { publicKey: pubKey, privateKey: privKey });
        return id;
      } catch (e) {
        return { error: "KEY_IMPORT_FAILED:" + e.message };
      }
    },

    "webcrypto:sig:sign": async ({ sigKeypairId, data }) => {
      const kp = signingKeypairs.get(sigKeypairId);
      if (!kp) return { error: "INVALID_KEY:SigningKeyPair not found" };
      try {
        const signature = await crypto.subtle.sign(
          { name: "ECDSA", hash: "SHA-256" },
          kp.privateKey,
          new Uint8Array(data),
        );
        return toBase64(new Uint8Array(signature));
      } catch (e) {
        return { error: "SIGNING_FAILED:" + e.message };
      }
    },

    "webcrypto:sig:verify": async ({ publicKeyJwk, signature, data }) => {
      try {
        const pubKey = await crypto.subtle.importKey(
          "jwk",
          JSON.parse(publicKeyJwk),
          { name: "ECDSA", namedCurve: "P-256" },
          true,
          ["verify"],
        );
        return await crypto.subtle.verify(
          { name: "ECDSA", hash: "SHA-256" },
          pubKey,
          fromBase64(signature),
          new Uint8Array(data),
        );
      } catch (e) {
        return { error: "VERIFICATION_FAILED:" + e.message };
      }
    },

    // --- Proof of Work ---

    "webcrypto:pow:solve": ({ challenge, difficulty }) => {
      return new Promise((resolve) => {
        const workerCode = `
          async function solve(challenge, difficulty) {
            const encoder = new TextEncoder();
            let nonce = 0;
            while (true) {
              const input = challenge + String(nonce);
              const hashBuffer = await crypto.subtle.digest(
                "SHA-256",
                encoder.encode(input)
              );
              const hashArray = new Uint8Array(hashBuffer);
              if (checkDifficulty(hashArray, difficulty)) {
                return String(nonce);
              }
              nonce++;
            }
          }

          function checkDifficulty(hashBytes, difficulty) {
            const fullBytes = Math.floor(difficulty / 8);
            const remainingBits = difficulty % 8;
            for (let i = 0; i < fullBytes; i++) {
              if (hashBytes[i] !== 0) return false;
            }
            if (remainingBits > 0) {
              const mask = 0xFF << (8 - remainingBits);
              if ((hashBytes[fullBytes] & mask) !== 0) return false;
            }
            return true;
          }

          self.onmessage = async (e) => {
            const { challenge, difficulty } = e.data;
            const nonce = await solve(challenge, difficulty);
            self.postMessage({ nonce });
          };
        `;
        const blob = new Blob([workerCode], {
          type: "application/javascript",
        });
        const worker = new Worker(URL.createObjectURL(blob));
        worker.onmessage = (e) => {
          worker.terminate();
          resolve(e.data.nonce);
        };
        worker.postMessage({ challenge, difficulty });
      });
    },
  };
}
