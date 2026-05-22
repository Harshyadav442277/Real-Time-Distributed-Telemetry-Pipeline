#include <HardwareSerial.h>
#define TINY_GSM_MODEM_SIM800
#include <TinyGsmClient.h>
#include <ESP_SSLClient.h>
#include <cstring>
#include <Crypto.h>
#include <ChaChaPoly.h>
#include <mbedtls/base64.h>
#include <esp_system.h>
#include <PubSubClient.h>

// ----------------------------
// Network Details
// ----------------------------
const char apn[]  = "internet";
const char user[] = "";
const char pass[] = "";

// ----------------------------
// ngrok TCP endpoint (from your console)y
// ----------------------------
const char tunnel_host[] = "0.tcp.in.ngrok.io";
const uint16_t tunnel_port = 13875;
const char mqtt_topic[] = "esp32/ingest";

// ======================================================================
// Paste your certs exactly in this format (line-by-line with \n)
// ======================================================================

const char my_cert[] =
"-----BEGIN CERTIFICATE-----\n"
"MIIC+jCCAeKgAwIBAgIUB+npPIgE8/eu8F8hU2Xq/yOSkpkwDQYJKoZIhvcNAQEL\n"
"BQAwEzERMA8GA1UEAwwITXlUZXN0Q0EwHhcNMjYwNDA2MTM0NzA4WhcNMjcwNDA2\n"
"MTM0NzA4WjAXMRUwEwYDVQQDDAxFU1AzMi1DbGllbnQwggEiMA0GCSqGSIb3DQEB\n"
"AQUAA4IBDwAwggEKAoIBAQC46eB4ME6T8kQOpqw4HV0n7tIyu7r3B0CNhSzZES6/\n"
"1C6IBBLj7CVZo4Io9r35yU+xn+HeVgwvk3O9ji/u8MVLb5xXm3VWy3kt1XHRyNJ2\n"
"TkUm8VaS6qcfLqT86jWXZpz0QBitf0YLLCVlW7MBvjt4C7TcZS4R5QMBXs833/iR\n"
"obZH56Yg/HpQhyj8toFX+CcZaUxzSOBWCQqLp9AbNfDP0AFRQw7eXjBnERBIxDi/\n"
"E93UWcmqohE8VHtUy9EKyqok5ktdQ9qp/Op/ldc4tpmzbrfcIHIm+qQw+4PAm0dW\n"
"l3SGhbDXT2N1/RYvG8/Bk4svq1F3OBpIy5FVmDsZKrD9AgMBAAGjQjBAMB0GA1Ud\n"
"DgQWBBQwZSKQHH80GiuaKBnGQwqMNNnDcTAfBgNVHSMEGDAWgBRCwAqGsHb/iY9a\n"
"eICXHt5m/v4cSDANBgkqhkiG9w0BAQsFAAOCAQEAa7Pr8Ry98bAMToaQXr2AtF7I\n"
"NDrRuWxK9BLDw9X/Sa5EeCY3EnzKKs4gkmMjuXoQolD6JEpDO1dsCZ/90xIbZw0O\n"
"xsbTi562GtI/AL1v4tJmZ7XV0ho85ny/5VtcEAg9iFtGtyVPmpjMjeNPRRmzjsVi\n"
"0uNckBP8cSRfj6tRaNOXNm2640I33AeyUWWgOqAUCTlzYZfSwM9dEXRnnsTtr6Mo\n"
"FC45teE1k1izCh06uVLg20BBgBlw5QnFh4jPpvL1epqbatNs2HQj+cAHEXktpOHO\n"
"43XQYVGigWagq5xlLCw7E6Zw8cWp6PYnbVhlhTnEiLH7CbH75x5tiLTpYNyOww==\n"
"-----END CERTIFICATE-----\n"
"\n";

const char my_key[] =
"-----BEGIN PRIVATE KEY-----\n"
"MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC46eB4ME6T8kQO\n"
"pqw4HV0n7tIyu7r3B0CNhSzZES6/1C6IBBLj7CVZo4Io9r35yU+xn+HeVgwvk3O9\n"
"ji/u8MVLb5xXm3VWy3kt1XHRyNJ2TkUm8VaS6qcfLqT86jWXZpz0QBitf0YLLCVl\n"
"W7MBvjt4C7TcZS4R5QMBXs833/iRobZH56Yg/HpQhyj8toFX+CcZaUxzSOBWCQqL\n"
"p9AbNfDP0AFRQw7eXjBnERBIxDi/E93UWcmqohE8VHtUy9EKyqok5ktdQ9qp/Op/\n"
"ldc4tpmzbrfcIHIm+qQw+4PAm0dWl3SGhbDXT2N1/RYvG8/Bk4svq1F3OBpIy5FV\n"
"mDsZKrD9AgMBAAECggEAA6mA9VmLkWs9O/TC7/eQ6KqfqhaOI7hx+g3SOFhRRX0q\n"
"EMBBC85irPsnFWfj3t1XJcgOwXXaYBKNA8HSx6EDg9kphZHK93ooSEu9O4sq2HRB\n"
"F6KQGboOr2YNcpWySwOHTzvnvKPmSLlcT/PKm9m6j+xuSS7W8hfsXGKohBaOqp+o\n"
"RYk0y8Tu1UuXhn0oTo1tew52PGL7Gl/LhomfUWS4PrRQ2kG8NCY7ygfEctXJubQR\n"
"grD9qo+2fVy6AnRz1sMP8eAdzGijteB/+LU1fZKTQRbM45CPCA552vlQ5YjiE09s\n"
"nPdKrG6BuQUdty85bg3Nf4/ozoH6iSaluG1TImfU1wKBgQDmzkHM+K9tEIwTVHvm\n"
"iAEqKuzF7vQ3FHL98TcVGsclUgf0OWKaqvzrhRiUxYuaa3shfrkBKocZr/lRwn7q\n"
"/1rOLfozo2dtb2NheM3mJrLGQBv1lGm5MY0peHrqxizTKmXEti4rPCuNTOyZYyRq\n"
"6jkBUCBMkgwzssXwYJhicZZLCwKBgQDNGTBl/V7sfd8rKxLuDCHd09tL9AXd60Iv\n"
"0KMqzdHkuXndDTkFck+g4lcBbj06Po+ieSw63A5OOCKmp5TRdiXThhckAZGtqnnz\n"
"aL6FCp6ilnaInWVCMvbYKi0FzFXgQ0j2OJYlOcDyq4bE9FsEu1QIlSV7WkKWqk0j\n"
"eKHg9q25FwKBgC/bcq9inVVbCgB0EyDQ8JTiw6ejDYZiOhnHq2k33TUy1i1gvL5f\n"
"WAQp29f1QiYpxSVD1m6Ud+DuqR632oM1oYmA5RFR/38kipHKb78aJRWQc3uvY2Cg\n"
"EqoXrj0CDIdYkjOApwAWAN3SpniDoyh8GofYKmpWGiuaFQrrrI01CjnTAoGBAIzj\n"
"H77/tKQptxK1TRSe2ujBrmPXZexSvi2QWXV+2w8OZer2OVRHePGgaXn/GyoWbZ6D\n"
"NGHeZilPIGZwuabFTSindN/z//lXINyW+ED10ZEIYLZpwHQgBDbrie/wtJEQR19z\n"
"8Zfyu1s3fqVu4dM3R3t50LySfSl4JPMX28NoUF/TAoGBAN2KWHCOV9Tzp4KsvJJU\n"
"6z0w27rabAp9HxEoGNggxpRr1UxawBLuqlOUfZwjF8b/v+mTr6zXuMvOtR/V2OBU\n"
"DPuxUV4/Bp/kFk3ASRPuPv8rASgNeOkuVjBOKE59saxwZo2eYYq8nDW97d7REx2W\n"
"7aFMyzR7HtOl+gMPwgEYx1FZ\n"
"-----END PRIVATE KEY-----\n"
"\n";

const char server_ca[] =
"-----BEGIN CERTIFICATE-----\n"
"MIIDBzCCAe+gAwIBAgIUaoD/RxSnegnTsMM12za21g3CqfQwDQYJKoZIhvcNAQEL\n"
"BQAwEzERMA8GA1UEAwwITXlUZXN0Q0EwHhcNMjYwNDA2MTM0NjQ0WhcNMjcwNDA2\n"
"MTM0NjQ0WjATMREwDwYDVQQDDAhNeVRlc3RDQTCCASIwDQYJKoZIhvcNAQEBBQAD\n"
"ggEPADCCAQoCggEBALmBgIXaL9tWh8jmtJdj4tlBe3MvGyob91OiSflrh693HqcQ\n"
"EMmbz81Tjgwb4iAMHWXJ7pchL9BPoG5ohhoXSktgda1EmoQQWVVz3E2MYFs71YA7\n"
"MqrtZsvEa4voTzg1nBHOlFRYcy42lJusTgzPYrdHHjLw/nbpen1+yrL3LDaML90N\n"
"jKOxKWhnccPaxXd/RC8ySbKdJ1WoBWyXZxynpxTmKmTiJCKCa7wHmmVPnXk+AFvy\n"
"w2aLKPTwta3hW4pbV9qg1Gr7zYCAtKg80J0rE6Zgp5WeaBazdE9y/HHIiVJfWJJ0\n"
"C9lpJCAiJC4W6v+EUGDQdX5v214+p77hmJXGd2cCAwEAAaNTMFEwHQYDVR0OBBYE\n"
"FELACoawdv+Jj1p4gJce3mb+/hxIMB8GA1UdIwQYMBaAFELACoawdv+Jj1p4gJce\n"
"3mb+/hxIMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBALj6ds/c\n"
"QYHWPlWZj9YrULDRL0MAmTtsavbh2PdWyqULNYpLJLLTrnHvV32jKKJ9VtAJs7Tn\n"
"fUS1UwuveYJOSAppUn6dfa1ZOposELfGmIZ3ewonYLsd//GQkWJ0yi6wGzdJ/OmE\n"
"lYtMVPuDWq8jwOSCQCT5+MkFHXzBtKFY9LkPB2pZdClbZ80XS6gIDDB/RAsh427R\n"
"vRlpE/SysTwE4afBJZ5+w2zSwbiiogAEFkGME4NjiFIXinH40TZlh+d5K95EGHri\n"
"gGdlEOMdsFduVzKQbo8hSs3l8i2bQuMiRPgwZoCf9baxoAHwLvsmCmbnc2b5KvMR\n"
"CX6yUkEdFPbzaNg=\n"
"-----END CERTIFICATE-----\n"
"\n";

// ======================================================================

#define SIM800L_RX 16
#define SIM800L_TX 17
HardwareSerial SerialGSM(2);

TinyGsm modem(SerialGSM);
TinyGsmClient raw_tcp_client(modem);
ESP_SSLClient secure_client;
PubSubClient mqttClient(secure_client);

// Set to true only for diagnostics to bypass server certificate validation.
const bool tls_insecure_mode = false;
// 2026-04-07 12:00:00 UTC. Must be within certificate validity window.
const uint32_t tls_x509_time = 1775563200;

const char pc_to_esp_key_hex[] = "ff112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const char esp_to_server_key_hex[] = "ffeeddccbbaa9988776655aa33221100ffeeddccccaa99117766554433221100";

uint8_t pc_to_esp_key[32];
uint8_t esp_to_server_key[32];

void printLastSslError() {
  char errBuf[192];
  memset(errBuf, 0, sizeof(errBuf));
  int code = secure_client.getLastSSLError(errBuf, sizeof(errBuf));
  Serial.print("[SSL] code=");
  Serial.print(code);
  Serial.print(" message=");
  Serial.println(errBuf);
}

bool hexToBytes(const char *hex, uint8_t *out, size_t outLen) {
  size_t hexLen = strlen(hex);
  if (hexLen != outLen * 2) {
    return false;
  }

  for (size_t i = 0; i < outLen; i++) {
    char high = hex[i * 2];
    char low = hex[i * 2 + 1];

    int highNibble = (high >= '0' && high <= '9') ? (high - '0') : ((high >= 'a' && high <= 'f') ? (high - 'a' + 10) : ((high >= 'A' && high <= 'F') ? (high - 'A' + 10) : -1));
    int lowNibble = (low >= '0' && low <= '9') ? (low - '0') : ((low >= 'a' && low <= 'f') ? (low - 'a' + 10) : ((low >= 'A' && low <= 'F') ? (low - 'A' + 10) : -1));

    if (highNibble < 0 || lowNibble < 0) {
      return false;
    }

    out[i] = (uint8_t)((highNibble << 4) | lowNibble);
  }

  return true;
}

String b64Encode(const uint8_t *input, size_t inputLen) {
  size_t outCap = ((inputLen + 2) / 3) * 4 + 4;
  unsigned char *out = (unsigned char *)malloc(outCap);
  if (!out) {
    return "";
  }

  size_t outLen = 0;
  int rc = mbedtls_base64_encode(out, outCap, &outLen, input, inputLen);
  if (rc != 0) {
    free(out);
    return "";
  }

  out[outLen] = '\0';
  String result = String((char *)out);
  free(out);
  return result;
}

int b64Decode(const String &input, uint8_t *out, size_t outCap) {
  size_t outLen = 0;
  int rc = mbedtls_base64_decode(out, outCap, &outLen, (const unsigned char *)input.c_str(), input.length());
  if (rc != 0) {
    return -1;
  } 

  return (int)outLen;
}

bool parsePacketLine(const String &line, String &nonceB64, String &cipherB64, String &tagB64) {
  int p1 = line.indexOf('|');
  int p2 = line.indexOf('|', p1 + 1);
  int p3 = line.indexOf('|', p2 + 1);

  if (p1 < 0 || p2 < 0 || p3 < 0) {
    return false;
  }

  String version = line.substring(0, p1);
  if (version != "v1") {
    return false;
  }

  nonceB64 = line.substring(p1 + 1, p2);
  cipherB64 = line.substring(p2 + 1, p3);
  tagB64 = line.substring(p3 + 1);
  tagB64.trim();

  return nonceB64.length() > 0 && cipherB64.length() > 0 && tagB64.length() > 0;
}

bool decryptFromPc(const String &line, String &plaintextOut) {
  String nonceB64, cipherB64, tagB64;
  if (!parsePacketLine(line, nonceB64, cipherB64, tagB64)) {
    Serial.println("[ERROR] Invalid input packet line format.");
    return false;
  }

  uint8_t nonce[12];
  uint8_t tag[16];
  uint8_t ciphertext[512];
  uint8_t plaintext[512];

  int nonceLen = b64Decode(nonceB64, nonce, sizeof(nonce));
  int tagLen = b64Decode(tagB64, tag, sizeof(tag));
  int ctLen = b64Decode(cipherB64, ciphertext, sizeof(ciphertext));

  if (nonceLen != 12 || tagLen != 16 || ctLen < 0) {
    Serial.println("[ERROR] Invalid nonce/tag/cipher lengths.");
    return false;
  }

  ChaChaPoly cipher;
  if (!cipher.setKey(pc_to_esp_key, sizeof(pc_to_esp_key))) {
    Serial.println("[ERROR] PC->ESP key setup failed.");
    return false;
  }

  if (!cipher.setIV(nonce, sizeof(nonce))) {
    Serial.println("[ERROR] PC->ESP nonce setup failed.");
    return false;
  }

  cipher.decrypt(plaintext, ciphertext, ctLen);
  if (!cipher.checkTag(tag, sizeof(tag))) {
    Serial.println("[ERROR] PC->ESP decrypt failed (tag/key mismatch).");
    return false;
  }

  plaintextOut = "";
  plaintextOut.reserve(ctLen);
  for (int i = 0; i < ctLen; i++) {
    plaintextOut += (char)plaintext[i];
  }

  return true;
}

bool encryptForServer(const String &plaintext, String &packetLineOut) {
  uint8_t nonce[12];
  for (int i = 0; i < 12; i++) {
    nonce[i] = (uint8_t)(esp_random() & 0xFF);
  }

  const uint8_t *plainBytes = (const uint8_t *)plaintext.c_str();
  size_t plainLen = plaintext.length();
  if (plainLen > 512) {
    Serial.println("[ERROR] Plaintext too large for configured buffer.");
    return false;
  }

  uint8_t ciphertext[512];
  uint8_t tag[16];

  ChaChaPoly cipher;
  if (!cipher.setKey(esp_to_server_key, sizeof(esp_to_server_key))) {
    Serial.println("[ERROR] ESP->Server key setup failed.");
    return false;
  }

  if (!cipher.setIV(nonce, sizeof(nonce))) {
    Serial.println("[ERROR] ESP->Server nonce setup failed.");
    return false;
  }

  cipher.encrypt(ciphertext, plainBytes, plainLen);
  cipher.computeTag(tag, sizeof(tag));

  String nonceB64 = b64Encode(nonce, sizeof(nonce));
  String cipherB64 = b64Encode(ciphertext, plainLen);
  String tagB64 = b64Encode(tag, sizeof(tag));

  if (nonceB64.length() == 0 || cipherB64.length() == 0 || tagB64.length() == 0) {
    Serial.println("[ERROR] Base64 encode failed.");
    return false;
  }

  packetLineOut = "v1|" + nonceB64 + "|" + cipherB64 + "|" + tagB64;
  return true;
}

bool publishPacketToMqtt(const String &packetLine) {
  if (!secure_client.connect(tunnel_host, tunnel_port)) {
    Serial.println("[ERROR] mTLS connect to MQTT broker failed.");
    printLastSslError();
    return false;
  }

  // ngrok random TCP ports are non-standard, so explicitly upgrade to TLS.
  if (!secure_client.isSecure()) {
    Serial.println("[INFO] Upgrading TCP connection to TLS...");
    if (!secure_client.connectSSL()) {
      Serial.println("[ERROR] TLS upgrade failed.");
      printLastSslError();
      secure_client.stop();
      return false;
    }
  }

  if (!secure_client.isSecure()) {
    Serial.println("[ERROR] Connection is still plain TCP (not TLS).");
    secure_client.stop();
    return false;
  }

  String clientId = "esp32-" + String((uint32_t)esp_random(), HEX);
  if (!mqttClient.connect(clientId.c_str())) {
    Serial.print("[ERROR] MQTT connect failed, state=");
    Serial.println(mqttClient.state());
    secure_client.stop();
    return false;
  }

  bool ok = mqttClient.publish(mqtt_topic, packetLine.c_str());
  mqttClient.loop();
  delay(500);
  mqttClient.loop();
  mqttClient.disconnect();
  secure_client.stop();
  if (!ok) {
    Serial.println("[ERROR] MQTT publish failed.");
    return false;
  }

  return true;
}

void setup() {
  Serial.begin(115200);
  Serial.setTimeout(250);
  delay(1000);

  Serial.println("\n--- ChaCha20-Poly1305 USB->ESP->Server Pipeline ---");

  if (!hexToBytes(pc_to_esp_key_hex, pc_to_esp_key, sizeof(pc_to_esp_key))) {
    Serial.println("[FATAL] Invalid PC_TO_ESP key hex.");
    while (true) {
      delay(1000);
    }
  }

  if (!hexToBytes(esp_to_server_key_hex, esp_to_server_key, sizeof(esp_to_server_key))) {
    Serial.println("[FATAL] Invalid ESP_TO_SERVER key hex.");
    while (true) {
      delay(1000);
    }
  }

  Serial.println("Initializing GSM UART...");
  SerialGSM.begin(115200, SERIAL_8N1, SIM800L_RX, SIM800L_TX);
  delay(3000);

  Serial.println("Initializing modem...");
  modem.init();

  Serial.print("Connecting to APN: ");
  Serial.println(apn);
  if (!modem.gprsConnect(apn, user, pass)) {
    Serial.println("[FATAL] GPRS Connection Failed.");
    while (true) {
      delay(1000);
    }
  }
  Serial.println("[OK] GPRS Connected Successfully!");

  Serial.println("Configuring SSL client...");
  secure_client.setClient(&raw_tcp_client);
  secure_client.setCACert(server_ca);
  secure_client.setCertificate(my_cert);
  secure_client.setPrivateKey(my_key);
  secure_client.setX509Time(tls_x509_time);
  secure_client.setTimeout(25000);
  secure_client.setDebugLevel(4);
  if (tls_insecure_mode) {
    Serial.println("[WARN] TLS insecure mode enabled for diagnostics.");
    secure_client.setInsecure();
  }

  mqttClient.setServer(tunnel_host, tunnel_port);
  mqttClient.setBufferSize(1024);

  Serial.println("Ready. Send one encrypted packet line over USB serial.");
}

void loop() {
  if (!Serial.available()) {
    return;
  }

  String inLine = Serial.readStringUntil('\n');
  inLine.trim();
  if (inLine.length() == 0) {
    return;
  }

  if (inLine.length() > 512) {
    Serial.println("[ERROR] Input too long.");
    return;
  }

  String nonceB64, cipherB64, tagB64;
  if (!parsePacketLine(inLine, nonceB64, cipherB64, tagB64)) {
    Serial.println("[ERROR] Invalid input packet line format.");
    return;
  }

  Serial.println("\n[PIPELINE] Packet received from USB.");

  String outPacket;
  if (!encryptForServer(inLine, outPacket)) {
    return;
  }

  Serial.println("[PIPELINE] Wrapped for server. Sending via MQTT...");
  if (publishPacketToMqtt(outPacket)) {
    Serial.println("[PIPELINE] Published to broker.");
  }
}
