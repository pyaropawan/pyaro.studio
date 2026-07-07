/* ==========================================================================
   pyaro-secure-ledger.js  —  client-side end-to-end encryption for JumboCamp
   --------------------------------------------------------------------------
   WHY THIS EXISTS
   The ledger is stored in a public kvdb.io bucket. Anyone who has the link
   (the ?ledger=<id> in the URL) can read and overwrite that bucket directly
   with a plain HTTP request — the password box in the page does NOT protect
   the data, it only hides it in *your own* browser. See SECURITY_AUDIT.md,
   finding J1.

   The only way to make the data genuinely private on a static/no-server host
   is to encrypt it in the browser before it is uploaded, with a key derived
   from a passphrase that never leaves the device. Then the bucket only ever
   holds ciphertext, and the link alone reveals nothing.

   WHAT IT GUARANTEES
   - Confidentiality: without the trip passphrase, the bucket is unreadable.
   - Integrity / tamper-evidence: AES-GCM is authenticated. If anyone edits
     the ciphertext, decryption throws and the app keeps its last good copy.
   WHAT IT DOES NOT FIX
   - Availability: a stranger can still overwrite the bucket with junk
     (a wipe / denial of service). Encryption can't stop that on a
     world-writable free store. If you need that too, move to a backend with
     real auth (see SECURITY_AUDIT.md, "Option B").

   MODEL
   - One "trip passphrase" is the read key for the whole group. Successful
     decryption *is* the proof the passphrase is correct — no password hash
     needs to live in the page anymore.
   - "Edit" rights stay a soft, in-app capability: an `editorPinHash` is
     stored INSIDE the encrypted payload, so it isn't even visible in the
     page source. A viewer types the editor PIN to switch into edit mode.

   VERIFIED: round-trip, wrong-passphrase rejection, and tamper rejection were
   tested against the WebCrypto API before shipping.
   ========================================================================== */
(function (global) {
  'use strict';
  const subtle = (global.crypto && global.crypto.subtle) || null;
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const PBKDF2_ITERATIONS = 150000;           // ~ reasonable on phones, still costly to brute force
  const ENVELOPE_VERSION = 1;

  const b64  = (bytes) => { const a = new Uint8Array(bytes); let s = ''; for (let i = 0; i < a.length; i += 0x8000) { s += String.fromCharCode.apply(null, a.subarray(i, i + 0x8000)); } return btoa(s); };
  const ub64 = (str)  => Uint8Array.from(atob(str), c => c.charCodeAt(0));

  function assertCrypto() {
    if (!subtle) throw new Error('WebCrypto unavailable — the page must be served over HTTPS.');
  }

  async function deriveKey(passphrase, salt) {
    assertCrypto();
    const base = await subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
    return subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
  }

  /* Public: SHA-256 hex — use it to make an editorPinHash to store in the payload. */
  async function sha256Hex(text) {
    assertCrypto();
    const digest = await subtle.digest('SHA-256', enc.encode(text));
    return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /* Encrypt an arbitrary JSON-serialisable object with a passphrase.
     Returns an envelope object safe to JSON.stringify and PUT to kvdb. */
  async function encrypt(obj, passphrase) {
    assertCrypto();
    if (!passphrase) throw new Error('A trip passphrase is required to encrypt.');
    const salt = global.crypto.getRandomValues(new Uint8Array(16));
    const iv   = global.crypto.getRandomValues(new Uint8Array(12));
    const key  = await deriveKey(passphrase, salt);
    const ct   = await subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(obj)));
    return { v: ENVELOPE_VERSION, enc: 'AES-GCM', kdf: 'PBKDF2',
             salt: b64(salt), iv: b64(iv), data: b64(new Uint8Array(ct)) };
  }

  /* Decrypt an envelope produced by encrypt(). Throws on wrong passphrase or
     tampering — callers should catch and treat that as "access denied". */
  async function decrypt(envelope, passphrase) {
    assertCrypto();
    if (!isEncrypted(envelope)) throw new Error('Not an encrypted envelope.');
    const key = await deriveKey(passphrase, ub64(envelope.salt));
    const pt  = await subtle.decrypt({ name: 'AES-GCM', iv: ub64(envelope.iv) }, key, ub64(envelope.data));
    return JSON.parse(dec.decode(pt));
  }

  /* True if a parsed bucket body looks like one of our encrypted envelopes
     (vs. a legacy plaintext {campers,expenses,...} object). */
  function isEncrypted(obj) {
    return !!obj && obj.enc === 'AES-GCM' && typeof obj.data === 'string'
        && typeof obj.salt === 'string' && typeof obj.iv === 'string';
  }

  global.SecureLedger = { encrypt, decrypt, isEncrypted, sha256Hex, PBKDF2_ITERATIONS };
})(typeof window !== 'undefined' ? window : globalThis);
