const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { SerialPort } = require('serialport');

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

function encryptChaCha20Poly1305(plaintext, key) {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('chacha20-poly1305', key, nonce, {
    authTagLength: 16,
  });

  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(plaintext, 'utf8')),
    cipher.final(),
  ]);

  const tag = cipher.getAuthTag();

  return {
    v: 1,
    alg: 'chacha20-poly1305',
    nonce: nonce.toString('base64'),
    ciphertext: ciphertext.toString('base64'),
    tag: tag.toString('base64'),
  };
}

function loadState(statePath) {
  try {
    const raw = fs.readFileSync(statePath, 'utf8');
    return JSON.parse(raw);
  } catch (err) {
    return { seq: 0 };
  }
}

function saveState(statePath, state) {
  fs.writeFileSync(statePath, JSON.stringify(state));
}

async function main() {
  const comPort = process.argv[2] || process.env.SERIAL_PORT;
  const textToSend = process.argv[3] || 'hello from pc over usb';
  const listenMs = Number(process.env.SERIAL_LISTEN_MS || 8000);
  const deviceId = process.env.DEVICE_ID;
  const eventType = process.env.EVENT_TYPE || 'TEST';
  const severity = process.env.SEVERITY || 'INFO';
  const maxMessageLength = Number(process.env.MAX_MESSAGE_LENGTH || 256);
  const maxInnerBytes = Number(process.env.MAX_INNER_BYTES || 512);
  const statePath = process.env.SENDER_STATE_PATH || path.join(__dirname, '.sender_state.json');
  const logPlaintext = process.env.LOG_PLAINTEXT === '1';
  const logCipher = process.env.LOG_CIPHER === '1';

  if (!comPort) {
    throw new Error('Provide COM port as argv[2] or set SERIAL_PORT (example: COM5).');
  }

  if (!deviceId) {
    throw new Error('Set DEVICE_ID to a stable device identifier.');
  }

  if (textToSend.length > maxMessageLength) {
    throw new Error(`Message too long. Max ${maxMessageLength} chars.`);
  }

  const state = loadState(statePath);
  const seq = Number.isInteger(state.seq) ? state.seq + 1 : 1;
  state.seq = seq;
  saveState(statePath, state);

  const payload = {
    schema: 'amc-alert-v1',
    device_id: deviceId,
    seq,
    timestamp_utc: new Date().toISOString(),
    event_type: eventType,
    severity,
    message: textToSend,
  };

  const payloadJson = JSON.stringify(payload);
  if (Buffer.byteLength(payloadJson, 'utf8') > maxInnerBytes) {
    throw new Error(`Inner payload too large. Max ${maxInnerBytes} bytes.`);
  }

  const key = mustGetKeyHex('PC_TO_ESP_KEY_HEX');
  const packet = encryptChaCha20Poly1305(payloadJson, key);
  const line = `v1|${packet.nonce}|${packet.ciphertext}|${packet.tag}\n`;

  const port = new SerialPort({
    path: comPort,
    baudRate: 115200,
    autoOpen: false,
  });

  await new Promise((resolve, reject) => {
    port.open((err) => (err ? reject(err) : resolve()));
  });

  let rxBuf = '';
  const onData = (chunk) => {
    rxBuf += chunk.toString('utf8');
    while (rxBuf.includes('\n')) {
      const idx = rxBuf.indexOf('\n');
      const lineOut = rxBuf.slice(0, idx).replace(/\r$/, '');
      rxBuf = rxBuf.slice(idx + 1);
      if (lineOut.trim().length > 0) {
        console.log('[ESP32]', lineOut);
      }
    }
  };

  port.on('data', onData);

  await new Promise((resolve, reject) => {
    port.write(line, (err) => {
      if (err) {
        reject(err);
        return;
      }
      port.drain((drainErr) => (drainErr ? reject(drainErr) : resolve()));
    });
  });

  await new Promise((resolve) => {
    setTimeout(resolve, listenMs);
  });

  port.off('data', onData);

  console.log('USB packet sent to ESP32.');
  console.log('Port:', comPort);
  console.log('Device ID:', deviceId);
  console.log('Seq:', seq);
  if (logPlaintext) {
    console.log('Plaintext:', textToSend);
  }
  if (logCipher) {
    console.log('Cipher line:', line.trim());
  }
  console.log(`Listen window: ${listenMs} ms`);

  port.close();
}

main().catch((err) => {
  console.error('pc_usb_sender failed:', err.message);
  process.exit(1);
});
