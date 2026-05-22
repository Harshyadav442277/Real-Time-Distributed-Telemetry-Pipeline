/*
  ESP32 + SIM800L network test for Arduino IDE

  What this sketch does:
  1) Tries SIM800L at common baud rates
  2) Checks SIM status, signal quality, and network registration
  3) Prints clear status messages in Serial Monitor
  4) Leaves a live AT command passthrough in loop()

  IMPORTANT:
  - SIM800L is 2G only.
  - Use a separate 3.7V to 4.2V supply capable of at least 2A peak.
  - Connect ESP32 GND and SIM800L GND together.
*/

// Arduino IDE settings:
// Board: ESP32 Dev Module
// Upload Speed: 921600 or 115200
// Flash Mode: QIO
// Flash Frequency: 80MHz
// Partition Scheme: Default 4MB with spiffs
// Core Debug Level: None
// PSRAM: Disabled unless your board has it

static const int SIM800L_RX = 16; // ESP32 RX2  <- SIM800L TX
static const int SIM800L_TX = 17; // ESP32 TX2  -> SIM800L RX

HardwareSerial sim800(2);

const unsigned long BAUD_CANDIDATES[] = {9600, 19200, 38400, 57600, 115200};
const size_t BAUD_COUNT = sizeof(BAUD_CANDIDATES) / sizeof(BAUD_CANDIDATES[0]);
unsigned long modemBaud = 0;

String readResponse(unsigned long waitMs = 1200) {
  String response = "";
  unsigned long start = millis();

  while (millis() - start < waitMs) {
    while (sim800.available()) {
      response += char(sim800.read());
    }
  }

  response.trim();
  return response;
}

String sendCommand(const String &command, unsigned long waitMs = 1200) {
  while (sim800.available()) {
    sim800.read();
  }

  sim800.println(command);
  return readResponse(waitMs);
}

bool responseLooksGood(const String &response) {
  return response.indexOf("OK") != -1 || response.indexOf("+CPIN:") != -1 || response.indexOf("+CSQ:") != -1;
}

bool tryBaud(unsigned long baud) {
  sim800.begin(baud, SERIAL_8N1, SIM800L_RX, SIM800L_TX);
  delay(1000);

  for (int i = 0; i < 3; i++) {
    String resp = sendCommand("AT", 1000);
    if (resp.indexOf("OK") != -1) {
      modemBaud = baud;
      return true;
    }
    delay(250);
  }

  return false;
}

void printCommandResult(const String &command, unsigned long waitMs = 1200) {
  String resp = sendCommand(command, waitMs);
  Serial.print(command);
  Serial.print(" => ");
  if (resp.length() == 0) {
    Serial.println("[NO RESPONSE]");
  } else {
    Serial.println(resp);
  }
}

bool isRegistered(const String &response) {
  return response.indexOf(",1") != -1 || response.indexOf(",5") != -1;
}

void printLine() {
  Serial.println("----------------------------------------");
}

void setup() {
  Serial.begin(115200);
  delay(1500);

  Serial.println();
  Serial.println("ESP32 + SIM800L starting...");
  Serial.println("Waiting for modem power-up...");
  delay(5000);

  bool modemFound = false;
  for (size_t i = 0; i < BAUD_COUNT; i++) {
    unsigned long baud = BAUD_CANDIDATES[i];
    Serial.print("Trying baud ");
    Serial.println(baud);
    if (tryBaud(baud)) {
      modemFound = true;
      Serial.print("Modem response found at ");
      Serial.println(modemBaud);
      break;
    }
  }

  printLine();
  if (!modemFound) {
    Serial.println("SIM800L did not answer at common baud rates.");
    Serial.println("Check wiring, supply voltage, and common ground.");
    Serial.println("If power is unstable, the modem may reboot and print garbage.");
    printLine();
    return;
  }

  printLine();
  Serial.println("AT check");
  printCommandResult("AT");
  printCommandResult("ATE0");
  printCommandResult("AT+CPIN?");
  printCommandResult("AT+CSQ");
  printCommandResult("AT+COPS?", 2000);
  printLine();

  Serial.println("Waiting for network registration");
  bool registered = false;
  for (int i = 1; i <= 15; i++) {
    String creg = sendCommand("AT+CREG?", 1200);
    Serial.print("Try ");
    Serial.print(i);
    Serial.print("/15, AT+CREG? => ");
    if (creg.length() == 0) {
      Serial.println("[NO RESPONSE]");
    } else {
      Serial.println(creg);
    }

    if (isRegistered(creg)) {
      registered = true;
      break;
    }

    delay(1500);
  }

  printLine();
  if (registered) {
    Serial.println("SIM800L is registered to the network.");
  } else {
    Serial.println("SIM800L is not registered yet.");
    Serial.println("If you still see under-voltage or no response, fix power first.");
  }
  printLine();

  Serial.println("Serial passthrough is active.");
  Serial.println("Type AT commands in Serial Monitor and use 'Both NL & CR'.");
}

void loop() {
  while (Serial.available()) {
    sim800.write(Serial.read());
  }

  while (sim800.available()) {
    Serial.write(sim800.read());
  }
}
