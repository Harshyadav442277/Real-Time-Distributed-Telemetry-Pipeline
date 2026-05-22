const tls = require('tls');
const fs = require('fs');
const crypto = require('crypto');
const aedes = require('aedes')();

function mustGetKeyHex(envName) {
  const keyHex = process.env[envName];
  if (!keyHex) {
    throw new Error(`${envName} is not set. Expected 64 hex chars (32-byte key).`);
  }

  if (!/^[0-9a-fA-F]{64}$/.test(keyHex)) {
    throw new Error(`${envName} must be exactly 64 hex characters.`);
  }

  return Buffer.from(keyHex, 'hex');
}

function decryptChaCha20Poly1305(packet, key) {
  if (!packet || packet.alg !== 'chacha20-poly1305') {
    throw new Error('Invalid packet algorithm.');
  }

  const nonce = Buffer.from(packet.nonce, 'base64');
  const ciphertext = Buffer.from(packet.ciphertext, 'base64');
  const tag = Buffer.from(packet.tag, 'base64');

  const decipher = crypto.createDecipheriv('chacha20-poly1305', key, nonce, {
    authTagLength: 16,
  });

  decipher.setAuthTag(tag);

  const plaintext = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);

  return plaintext.toString('utf8');
}

function parseLinePacket(line) {
  const trimmed = String(line || '').trim();
  const parts = trimmed.split('|');

  if (parts.length !== 4 || parts[0] !== 'v1') {
    throw new Error('Invalid packet line format. Expected v1|nonce|ciphertext|tag');
  }

  return {
    alg: 'chacha20-poly1305',
    nonce: parts[1],
    ciphertext: parts[2],
    tag: parts[3],
  };
}

const hop1Key = mustGetKeyHex('PC_TO_ESP_KEY_HEX');
const hop2Key = mustGetKeyHex('ESP_TO_SERVER_KEY_HEX');

const allowedTopics = new Set(
  String(process.env.ALLOWED_TOPICS || 'esp32/ingest')
    .split(',')
    .map((topic) => topic.trim())
    .filter(Boolean)
);

const allowedClientIds = new Set(
  String(process.env.ALLOWED_CLIENT_IDS || '')
    .split(',')
    .map((id) => id.trim())
    .filter(Boolean)
);

const allowedClientPrefixes = new Set(
  String(process.env.ALLOWED_CLIENT_ID_PREFIXES || '')
    .split(',')
    .map((prefix) => prefix.trim())
    .filter(Boolean)
);

const allowedCertFingerprints = new Set(
  String(process.env.ALLOWED_CERT_FINGERPRINTS || '')
    .split(',')
    .map((fp) => fp.trim().toUpperCase())
    .filter(Boolean)
);

const requireAllowlist = process.env.REQUIRE_ALLOWLIST !== '0';
const allowSeqReset = process.env.ALLOW_SEQ_RESET === '1';
const maxOuterBytes = Number(process.env.MAX_OUTER_BYTES || 2048);
const maxInnerBytes = Number(process.env.MAX_INNER_BYTES || 512);
const maxMessageLength = Number(process.env.MAX_MESSAGE_LENGTH || 256);
const maxClockSkewMs = Number(process.env.MAX_CLOCK_SKEW_MS || 10 * 60 * 1000);
const maxMessagesPerMinute = Number(process.env.MAX_MESSAGES_PER_MIN || 60);
const logPlaintext = process.env.LOG_PLAINTEXT === '1';

const keyPath = process.env.SERVER_KEY_PATH || 'server-key.pem';
const certPath = process.env.SERVER_CERT_PATH || 'server-cert.pem';
const caPath = process.env.CA_CERT_PATH || 'ca-cert.pem';

const options = {
  key: fs.readFileSync(keyPath),
  cert: fs.readFileSync(certPath),
  ca: fs.readFileSync(caPath),
  requestCert: true,
  rejectUnauthorized: true,
  minVersion: 'TLSv1.2',
};

if (requireAllowlist && allowedClientIds.size === 0 && allowedClientPrefixes.size === 0 && allowedCertFingerprints.size === 0) {
  throw new Error('No MQTT allowlist configured. Set ALLOWED_CLIENT_IDS, ALLOWED_CLIENT_ID_PREFIXES, or ALLOWED_CERT_FINGERPRINTS.');
}

const server = tls.createServer(options, aedes.handle);

function getClientFingerprint(client) {
  if (!client || !client.conn || typeof client.conn.getPeerCertificate !== 'function') {
    return '';
  }

  const cert = client.conn.getPeerCertificate();
  if (!cert) {
    return '';
  }

  return String(cert.fingerprint256 || cert.fingerprint || '').toUpperCase();
}

function isClientAllowed(client) {
  if (!client) {
    return false;
  }

  if (allowedClientIds.has(client.id)) {
    return true;
  }

  for (const prefix of allowedClientPrefixes) {
    if (client.id && client.id.startsWith(prefix)) {
      return true;
    }
  }

  const fp = getClientFingerprint(client);
  if (fp && allowedCertFingerprints.has(fp)) {
    return true;
  }

  return !requireAllowlist;
}

const lastSeqByDevice = new Map();
const rateWindowByDevice = new Map();

function isRateLimited(deviceId) {
  const now = Date.now();
  const window = rateWindowByDevice.get(deviceId) || { start: now, count: 0 };
  if (now - window.start > 60 * 1000) {
    window.start = now;
    window.count = 0;
  }

  window.count += 1;
  rateWindowByDevice.set(deviceId, window);
  return window.count > maxMessagesPerMinute;
}

function parseInnerMessage(innerText) {
  if (Buffer.byteLength(innerText, 'utf8') > maxInnerBytes) {
    throw new Error('Inner payload too large.');
  }

  let msg;
  try {
    msg = JSON.parse(innerText);
  } catch (err) {
    throw new Error('Inner payload is not valid JSON.');
  }

  const requiredKeys = ['schema', 'device_id', 'seq', 'timestamp_utc', 'event_type', 'severity', 'message'];
  const allowedKeys = new Set([...requiredKeys]);

  for (const key of Object.keys(msg)) {
    if (!allowedKeys.has(key)) {
      throw new Error(`Unexpected field: ${key}`);
    }
  }

  for (const key of requiredKeys) {
    if (!(key in msg)) {
      throw new Error(`Missing field: ${key}`);
    }
  }

  if (msg.schema !== 'amc-alert-v1') {
    throw new Error('Invalid schema value.');
  }

  if (typeof msg.device_id !== 'string' || msg.device_id.length === 0 || msg.device_id.length > 64) {
    throw new Error('Invalid device_id.');
  }

  if (!Number.isInteger(msg.seq) || msg.seq < 0) {
    throw new Error('Invalid seq.');
  }

  if (typeof msg.timestamp_utc !== 'string') {
    throw new Error('Invalid timestamp_utc.');
  }

  const ts = Date.parse(msg.timestamp_utc);
  if (Number.isNaN(ts)) {
    throw new Error('timestamp_utc is not parseable.');
  }

  const skew = Math.abs(Date.now() - ts);
  if (skew > maxClockSkewMs) {
    throw new Error('timestamp_utc outside allowed clock skew.');
  }

  if (typeof msg.event_type !== 'string' || msg.event_type.length === 0 || msg.event_type.length > 64) {
    throw new Error('Invalid event_type.');
  }

  if (typeof msg.severity !== 'string' || msg.severity.length === 0 || msg.severity.length > 16) {
    throw new Error('Invalid severity.');
  }

  if (typeof msg.message !== 'string' || msg.message.length === 0 || msg.message.length > maxMessageLength) {
    throw new Error('Invalid message length.');
  }

  const lastSeq = lastSeqByDevice.get(msg.device_id);
  if (lastSeq !== undefined && msg.seq <= lastSeq) {
    if (!allowSeqReset) {
      throw new Error('Replay detected (seq not increasing).');
    }
  }

  lastSeqByDevice.set(msg.device_id, msg.seq);
  return msg;
}

aedes.authenticate = (client, username, password, callback) => {
  if (!isClientAllowed(client)) {
    return callback(new Error('Client not allowlisted'), false);
  }

  return callback(null, true);
};

aedes.authorizePublish = (client, packet, callback) => {
  if (!isClientAllowed(client)) {
    return callback(new Error('Client not allowlisted'));
  }

  if (!allowedTopics.has(packet.topic)) {
    return callback(new Error('Topic not allowed'));
  }

  return callback(null);
};

aedes.on('client', (client) => {
  console.log('\n[MQTT CONNECT] Client id:', client ? client.id : 'n/a');
});

aedes.on('clientDisconnect', (client) => {
  console.log('[MQTT DISCONNECT] Client id:', client ? client.id : 'n/a');
});

aedes.on('error', (err) => {
  console.log('[MQTT ERROR]:', err ? err.message : 'unknown');
});

aedes.on('publish', (packet, client) => {
  if (!client) {
    return;
  }

  if (packet.topic && packet.topic.startsWith('$SYS')) {
    return;
  }

  if (!allowedTopics.has(packet.topic)) {
    console.log('[WARN] Publish to disallowed topic:', packet.topic || 'n/a');
    return;
  }

  if (typeof packet.payload === 'string' && packet.payload.length > maxOuterBytes) {
    console.log('[WARN] Dropping oversized payload.');
    return;
  }

  const payload = Buffer.isBuffer(packet.payload)
    ? packet.payload.toString('utf8')
    : String(packet.payload || '');

  if (Buffer.byteLength(payload, 'utf8') > maxOuterBytes) {
    console.log('[WARN] Dropping oversized payload.');
    return;
  }

  try {
    const outerPacket = parseLinePacket(payload);
    const innerLine = decryptChaCha20Poly1305(outerPacket, hop2Key);
    const innerPacket = parseLinePacket(innerLine);
    const innerPlaintext = decryptChaCha20Poly1305(innerPacket, hop1Key);
    const parsed = parseInnerMessage(innerPlaintext);

    if (isRateLimited(parsed.device_id)) {
      throw new Error('Rate limit exceeded.');
    }

    console.log('\n[SUCCESS] MQTT + double decrypt OK');
    console.log('Client id:', client ? client.id : 'n/a');
    console.log('Topic:', packet.topic || 'n/a');
    if (logPlaintext) {
      console.log('[Decrypted from PC]:', parsed.message);
    }
  } catch (err) {
    console.log('\n[ERROR] Payload decrypt failed:', err.message);
  }
});

server.on('tlsClientError', (err, tlsSocket) => {
  console.log('\n[TLS HANDSHAKE FAILED]:', err.message);
  console.log('[TLS code]:', err.code || 'n/a');
  if (tlsSocket) {
    console.log('[TLS socket authorized]:', tlsSocket.authorized);
    console.log('[TLS authorizationError]:', tlsSocket.authorizationError || 'n/a');
  }
});

server.listen(4433, () => {
  console.log('mTLS MQTT broker listening on port 4433...');
});
