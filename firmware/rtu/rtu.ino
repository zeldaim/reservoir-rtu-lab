// 무인 배수지 원격감시 장치(RTU) — 2단계: FreeRTOS 작업 분리 (Wokwi · ESP32)
//
//  출입통제  버튼 4개 PIN · 레이트 리밋 잠금(60초 5회 → 30초, 반복 시 2배) · 출입문 서보
//            PIR 침입 감지 — 인증 없이 움직임이 있으면 INTRUSION
//  공정      초음파 = 수위계 (탱크 깊이 200cm) · 서보 = 유출 밸브 · 파란 LED = 유입 펌프
//            자동 제어: 수위 170cm 넘으면 밸브 열고 펌프 끔 / 50cm 아래면 밸브 닫고 펌프 켬
//            경보: 190cm 넘음(넘침 위험) · 20cm 아래(고갈) · 1초에 30cm 넘게 변함(센서 조작 · 누수 의심)
//  사건 기록 메모리 + 시리얼 한 줄 JSON (3단계에서 서버로 전송 · 서명)
//
// 왜 FreeRTOS 로 나누나: 3단계에서 사건을 서버로 보내면 통신(1~3초) 동안 loop() 하나짜리 구조는
// 버튼 · 침입 감지 · **수위 제어까지 멈춘다** — 물이 넘쳐도 밸브를 못 연다. 그래서:
//
//   process 우선순위 4  수위 측정 · 밸브 · 펌프 · 공정 경보 · 모터 과열 인터록(LM35 70°C)   ← 제일 중요 (안전)
//   input   우선순위 3  버튼 · 출입 상태 · LCD 1줄
//   sound   우선순위 3  부저
//   sensor  우선순위 2  PIR 침입 감지 · 설비실 온습도(DHT: 40°C↑ 과열 · 85%↑ 결로/침수)
//   net     우선순위 1  사건 전송 (지금은 2초 걸리는 가짜 전송 · 3단계에서 실제 HTTP)
//   console 우선순위 1  시리얼 명령(log · stat) · 10초마다 STAT
//
// 측정: process · input 작업이 한 바퀴 도는 간격의 최댓값을 10초마다 STAT 으로 출력.
//   NET_IN_LOOP 0 (기본) : 전송은 net 작업이 함                          → 간격 수십 ms 이하
//   NET_IN_LOOP 1        : 사건을 만든 작업이 직접 전송함 (1단계 구조) → 간격 ≈ 2000ms

#include <Wire.h>
#include <LiquidCrystal_I2C.h>
#include <ESP32Servo.h>
#include <DHT.h>                           // Adafruit DHT sensor library (수업 11주차 온습도 센서)

// Wokwi 에는 DHT22 만 있다 — 실물 DHT11 이면 DHT11 로 바꾼다 (배선 · 코드는 같음)
#ifndef DHT_TYPE
#define DHT_TYPE DHT22
#endif

#ifndef NET_IN_LOOP
#define NET_IN_LOOP 0
#endif

// ── 핀 ───────────────────────────────────────────────
const int BTN_PINS[4] = {13, 12, 14, 27};  // 조작반 버튼 1~4 (다른 쪽 GND, 내부 풀업)
const int PIN_DOOR    = 18;                // 출입문 서보
const int PIN_VALVE   = 23;                // 유출 밸브 서보
const int PIN_PUMP    = 32;                // 유입 펌프 (파란 LED)
const int PIN_BUZZER  = 19;
const int PIN_TRIG    = 5;                 // 수위계 (초음파)
const int PIN_ECHO    = 17;
const int PIN_PIR     = 33;                // 침입 감지
const int PIN_DHT     = 16;                // 설비실 온습도 (DHT)
const int PIN_LM35    = 34;                // 펌프 모터 온도 (LM35 · Wokwi 에선 가변저항). ADC1 핀 — ADC2 는 Wi-Fi 와 충돌
const int PIN_LED_OK  = 25;
const int PIN_LED_NG  = 26;

// ── 출입통제 설정 ────────────────────────────────────
const char PASSWORD[5]       = "2413";
const int  PW_LEN            = 4;
const uint32_t OPEN_MS       = 5000;
const int  FAIL_LIMIT        = 5;
const uint32_t FAIL_WINDOW   = 60000;
const uint32_t LOCKOUT_BASE  = 30000;
const uint32_t AUTH_GRACE_MS = 60000;      // 인증 성공 뒤 이 시간 안의 움직임은 정상 출입
const uint32_t DEBOUNCE_MS   = 40;
const uint32_t MSG_MS        = 800;

// ── 공정 설정 ────────────────────────────────────────
const int TANK_CM       = 200;             // 탱크 깊이 (센서는 위에 달려 있음: 수위 = 깊이 - 거리)
const int LEVEL_HIGH    = 170;             // 이 위면 밸브 열고 펌프 끔
const int LEVEL_LOW     = 50;              // 이 아래면 밸브 닫고 펌프 켬
const int LEVEL_HH      = 190;             // 넘침 경보
const int LEVEL_LL      = 20;              // 고갈 경보
const int JUMP_CM_PER_S = 30;              // 1초에 이만큼 넘게 변하면 이상
const uint32_t PROCESS_MS = 200;
const float MOTOR_HOT_C   = 70.0;          // 인터록: 펌프 모터가 이 위면 펌프 강제 정지
const float MOTOR_RESET_C = 60.0;          //   이 아래로 식어야 다시 돌 수 있음 (히스테리시스)

// ── 설비실 환경 설정 ─────────────────────────────────
const float ENV_HOT_C      = 40.0;         // 이 위면 설비(펌프 · 제어반) 과열 위험
const float ENV_HUMID_PCT  = 85.0;         // 이 위면 결로 · 침수 의심
const uint32_t ENV_READ_MS = 2000;         // DHT22 는 2초, DHT11 은 1초에 한 번까지

const uint32_t FAKE_NET_MS   = 2000;
const uint32_t STAT_EVERY_MS = 10000;

LiquidCrystal_I2C lcd(0x27, 16, 2);
Servo door, valve;
DHT dht(PIN_DHT, DHT_TYPE);

// ── 작업 사이 통로 ───────────────────────────────────
struct Event { uint32_t ms; char type[12]; char detail[32]; };
struct Sound { uint16_t freq; uint16_t ms; uint8_t count; };

QueueHandle_t eventQ, soundQ;
SemaphoreHandle_t lcdMutex, logMutex;
TaskHandle_t hProcess, hInput, hSound, hSensor, hNet, hConsole;

volatile uint32_t lastAuthAt = 0;          // input 이 쓰고 sensor 가 읽음 (0 = 아직 없음)
volatile bool     doorOpen   = false;
volatile uint32_t gapInputUs = 0, gapProcessUs = 0;
volatile uint32_t netSent    = 0;
volatile int      levelNow   = -1;
volatile float    tempNow    = NAN, humNow = NAN, motorNow = NAN;

// ── 사고 기록 ────────────────────────────────────────
const int LOG_MAX = 50;
Event logBuf[LOG_MAX];
int logCount = 0, logHead = 0;

// 주의: Arduino 는 함수 선언을 파일 맨 위에 자동으로 만들어 넣는다 — 그래서 함수 인자에 이 파일의 struct(Event 등)를
// 쓰면 'does not name a type' 오류가 난다. 인자에는 기본 타입만 쓰고, 기본값 인자(= 1)도 쓰지 않는다.
void fakeNetworkSend() {                   // 3단계: 서버로 HTTP POST (서명 포함) — 그때 보낼 사건을 큐에서 꺼내 넘긴다
  vTaskDelay(pdMS_TO_TICKS(FAKE_NET_MS));
  netSent = netSent + 1;                   // net 작업만 씀 (volatile 에 ++ 는 경고)
}

void logEvent(const char* type, const char* detail) {
  Event e;
  e.ms = millis();
  strlcpy(e.type, type, sizeof(e.type));
  strlcpy(e.detail, detail, sizeof(e.detail));

  xSemaphoreTake(logMutex, portMAX_DELAY);
  logBuf[logHead] = e;
  logHead = (logHead + 1) % LOG_MAX;
  if (logCount < LOG_MAX) logCount++;
  Serial.printf("EVENT {\"t\":%lu,\"type\":\"%s\",\"detail\":\"%s\"}\n",
                (unsigned long)(e.ms / 1000), e.type, e.detail);
  xSemaphoreGive(logMutex);

#if NET_IN_LOOP
  fakeNetworkSend();                       // 1단계 구조: 부른 작업이 전송 끝날 때까지 멈춤
#else
  if (xQueueSend(eventQ, &e, 0) != pdTRUE) {   // 큐가 차면 기다리지 않음 (제어가 우선)
    xSemaphoreTake(logMutex, portMAX_DELAY);
    Serial.println("WARN 사건 큐가 가득 참 — 전송 못 한 사건은 기록에만 남음");
    xSemaphoreGive(logMutex);
  }
#endif
}

void printLog() {
  xSemaphoreTake(logMutex, portMAX_DELAY);
  Serial.printf("=== 사고 기록 %d건 ===\n", logCount);
  int start = (logHead - logCount + LOG_MAX) % LOG_MAX;
  for (int i = 0; i < logCount; i++) {
    const Event& e = logBuf[(start + i) % LOG_MAX];
    Serial.printf("T+%02lu:%02lu  %-10s %s\n", (unsigned long)(e.ms / 60000),
                  (unsigned long)((e.ms / 1000) % 60), e.type, e.detail);
  }
  xSemaphoreGive(logMutex);
}

void printStat() {
  uint32_t gi = gapInputUs, gp = gapProcessUs;
  gapInputUs = 0; gapProcessUs = 0;
  xSemaphoreTake(logMutex, portMAX_DELAY);
  // stack_free_B = 그 작업이 지금까지 가장 깊이 썼을 때 남은 바이트 (0 에 가까우면 넘칠 위험)
  Serial.printf("STAT mode=%s gap_max_ms process=%.1f input=%.1f level_cm=%d motor_c=%.1f room_c=%.1f room_hum_pct=%.1f"
                " stack_free_B process=%u input=%u sound=%u sensor=%u net=%u console=%u"
                " heap_free_B=%u net_sent=%u net_queue=%u\n",
                NET_IN_LOOP ? "net_in_loop" : "tasks", gp / 1000.0, gi / 1000.0, levelNow, motorNow, tempNow, humNow,
                (unsigned)uxTaskGetStackHighWaterMark(hProcess), (unsigned)uxTaskGetStackHighWaterMark(hInput),
                (unsigned)uxTaskGetStackHighWaterMark(hSound), (unsigned)uxTaskGetStackHighWaterMark(hSensor),
                (unsigned)uxTaskGetStackHighWaterMark(hNet), (unsigned)uxTaskGetStackHighWaterMark(hConsole),
                (unsigned)ESP.getFreeHeap(), (unsigned)netSent, (unsigned)uxQueueMessagesWaiting(eventQ));
  xSemaphoreGive(logMutex);
}

// ── LCD (1줄 = 출입 · 2줄 = 공정) · 소리 ─────────────
void showLine(int row, const char* text) {
  char pad[17];
  snprintf(pad, sizeof(pad), "%-16s", text);   // 남은 칸은 공백으로 지움
  xSemaphoreTake(lcdMutex, portMAX_DELAY);
  lcd.setCursor(0, row);
  lcd.print(pad);
  xSemaphoreGive(lcdMutex);
}

void sound(uint16_t freq, uint16_t ms, uint8_t count) {
  Sound s = {freq, ms, count};
  xQueueSend(soundQ, &s, 0);
}

void soundTask(void*) {
  Sound s;
  for (;;) {
    if (xQueueReceive(soundQ, &s, portMAX_DELAY) == pdTRUE) {
      for (int i = 0; i < s.count; i++) {
        tone(PIN_BUZZER, s.freq, s.ms);
        vTaskDelay(pdMS_TO_TICKS(s.ms + 50));
      }
    }
  }
}

void trackGap(volatile uint32_t& maxGap, int64_t& last) {
  int64_t t = esp_timer_get_time();
  uint32_t gap = (uint32_t)(t - last);
  if (gap > maxGap) maxGap = gap;
  last = t;
}

// ── process 작업: 수위 · 밸브 · 펌프 ─────────────────
long readDistanceCm() {
  digitalWrite(PIN_TRIG, LOW);  delayMicroseconds(2);
  digitalWrite(PIN_TRIG, HIGH); delayMicroseconds(10);
  digitalWrite(PIN_TRIG, LOW);
  long us = pulseIn(PIN_ECHO, HIGH, 30000);
  return us == 0 ? -1 : us / 58;
}

// LM35: 1°C 당 10mV. analogReadMilliVolts 는 ESP32 가 보정한 mV (우노라면 analogRead()*5.0/1024*100)
float readMotorTempC() {
  return analogReadMilliVolts(PIN_LM35) / 10.0;
}

void processTask(void*) {
  bool valveOpen = false, pumpOn = false;
  bool interlock = false;                  // 모터 과열로 펌프 강제 정지 중
  bool hhActive = false, llActive = false, sensorErr = false;
  int lastLevel = -1;
  uint32_t lastLevelAt = 0;
  int64_t lastIter = esp_timer_get_time();
  char d[32];

  for (;;) {
    trackGap(gapProcessUs, lastIter);
    uint32_t now = millis();
    long dist = readDistanceCm();

    if (dist < 0) {
      if (!sensorErr) logEvent("SENSOR_ERR", "level sensor no echo");   // 들어갈 때 한 번
      sensorErr = true;
      digitalWrite(PIN_PUMP, LOW);         // 안전 쪽으로: 수위를 모르면 펌프를 끈다 (넘침 방지)
      showLine(1, "LEVEL SENSOR ERR");
    } else {
      sensorErr = false;
      int level = constrain(TANK_CM - (int)dist, 0, TANK_CM);
      levelNow = level;

      // 변화 속도 — 물리적으로 불가능하게 빠르면 센서 조작 · 누수 의심
      if (lastLevel >= 0 && now > lastLevelAt) {
        int rate = abs(level - lastLevel) * 1000 / (int)(now - lastLevelAt);
        if (rate > JUMP_CM_PER_S) {
          snprintf(d, sizeof(d), "%d->%dcm %dcm/s", lastLevel, level, rate);
          logEvent("LEVEL_JUMP", d);
        }
      }
      lastLevel = level; lastLevelAt = now;

      // 자동 제어 (히스테리시스: HIGH 와 LOW 사이에서는 지금 상태 유지)
      if (level >= LEVEL_HIGH && (!valveOpen || pumpOn)) {
        valveOpen = true; pumpOn = false;
        snprintf(d, sizeof(d), "L%d valve open pump off", level);
        logEvent("CONTROL", d);
      } else if (level <= LEVEL_LOW && (valveOpen || !pumpOn)) {
        valveOpen = false; pumpOn = true;
        snprintf(d, sizeof(d), "L%d valve shut pump on", level);
        logEvent("CONTROL", d);
      }
      // 인터록: 모터가 뜨거우면 제어 판단과 상관없이 펌프를 끈다 (식을 때까지)
      float motor = readMotorTempC();
      motorNow = motor;
      if (!interlock && motor >= MOTOR_HOT_C) {
        interlock = true;
        snprintf(d, sizeof(d), "motor %.0fC pump forced off", motor);
        logEvent("INTERLOCK", d);
        sound(1500, 400, 3);
      } else if (interlock && motor <= MOTOR_RESET_C) {
        interlock = false;
        snprintf(d, sizeof(d), "motor %.0fC pump allowed", motor);
        logEvent("INTERLOCK", d);
      }

      valve.write(valveOpen ? 90 : 0);
      digitalWrite(PIN_PUMP, (pumpOn && !interlock) ? HIGH : LOW);

      // 공정 경보 (들어갈 때 한 번)
      if (level >= LEVEL_HH && !hhActive) {
        snprintf(d, sizeof(d), "HH %dcm overflow risk", level);
        logEvent("ALARM", d);
        sound(1800, 300, 2);
      }
      if (level <= LEVEL_LL && !llActive) {
        snprintf(d, sizeof(d), "LL %dcm tank low", level);
        logEvent("ALARM", d);
        sound(500, 300, 2);
      }
      hhActive = level >= LEVEL_HH;
      llActive = level <= LEVEL_LL;

      char l2[17];
      snprintf(l2, sizeof(l2), "L%3d V%s P%s", level, valveOpen ? "OPN" : "SHT",
               interlock ? "IL" : (pumpOn ? "ON" : "OF"));       // IL = 인터록으로 정지
      showLine(1, l2);
    }
    vTaskDelay(pdMS_TO_TICKS(PROCESS_MS));
  }
}

// ── input 작업: 조작반 PIN · 출입문 ──────────────────
enum State { LOCKED, OPEN, LOCKOUT };
State state = LOCKED;
uint32_t stateUntil = 0, msgUntil = 0;
char input[PW_LEN + 1] = "";
int inputLen = 0;
uint32_t failTimes[FAIL_LIMIT];
int failIdx = 0, failCount = 0, lockoutCount = 0;

void showInput() {
  char stars[PW_LEN + 1];
  for (int i = 0; i < PW_LEN; i++) stars[i] = (i < inputLen) ? '*' : '_';   // PIN 은 화면에 안 보이게
  stars[PW_LEN] = '\0';
  char l1[17];
  snprintf(l1, sizeof(l1), "PIN %s", stars);
  showLine(0, l1);
}

bool checkPassword() {                     // 끝까지 비교 (응답 시간으로 자릿수 추측 방지)
  int diff = 0;
  for (int i = 0; i < PW_LEN; i++) diff |= (input[i] ^ PASSWORD[i]);
  return diff == 0;
}

int recentFailures(uint32_t now) {
  int n = 0;
  for (int i = 0; i < failCount; i++)
    if (now - failTimes[i] <= FAIL_WINDOW) n++;
  return n;
}

void onWrongPassword(uint32_t now) {
  failTimes[failIdx] = now;
  failIdx = (failIdx + 1) % FAIL_LIMIT;
  if (failCount < FAIL_LIMIT) failCount++;
  int n = recentFailures(now);
  char d[32];
  snprintf(d, sizeof(d), "%d/%d in 60s", n, FAIL_LIMIT);
  logEvent("FAIL", d);
  digitalWrite(PIN_LED_NG, HIGH);

  if (n >= FAIL_LIMIT) {
    uint32_t dur = LOCKOUT_BASE << min(lockoutCount, 4);
    lockoutCount++;
    state = LOCKOUT;
    stateUntil = now + dur;
    failCount = 0; failIdx = 0;
    snprintf(d, sizeof(d), "#%d %lus", lockoutCount, (unsigned long)(dur / 1000));
    logEvent("LOCKOUT", d);
    sound(1000, 150, 3);
  } else {
    sound(300, 300, 1);
    char l1[17];
    snprintf(l1, sizeof(l1), "DENIED %d/%d", n, FAIL_LIMIT);
    showLine(0, l1);
    msgUntil = now + MSG_MS;
  }
}

void onKey(int key, uint32_t now) {
  if (state == LOCKOUT) { logEvent("KEY_LOCKED", "input during lockout"); sound(200, 80, 1); return; }
  if (state == OPEN) return;
  if (msgUntil) { msgUntil = 0; digitalWrite(PIN_LED_NG, LOW); }

  sound(1500, 30, 1);
  input[inputLen++] = '0' + key;
  input[inputLen] = '\0';
  showInput();
  if (inputLen < PW_LEN) return;

  if (checkPassword()) {
    state = OPEN;
    stateUntil = now + OPEN_MS;
    failCount = 0; failIdx = 0;
    lastAuthAt = now;
    doorOpen = true;
    logEvent("OPEN", "pin ok");
    door.write(90);
    digitalWrite(PIN_LED_OK, HIGH);
    sound(2000, 100, 1);
    showLine(0, "DOOR OPEN");
  } else {
    onWrongPassword(now);
  }
  inputLen = 0; input[0] = '\0';
}

void inputTask(void*) {
  bool btnLast[4] = {HIGH, HIGH, HIGH, HIGH};
  uint32_t btnChanged[4] = {0, 0, 0, 0};
  uint32_t lastDraw = 0;
  int64_t lastIter = esp_timer_get_time();
  showInput();

  for (;;) {
    trackGap(gapInputUs, lastIter);
    uint32_t now = millis();

    for (int i = 0; i < 4; i++) {
      bool v = digitalRead(BTN_PINS[i]);
      if (v != btnLast[i] && now - btnChanged[i] > DEBOUNCE_MS) {
        btnChanged[i] = now;
        btnLast[i] = v;
        if (v == LOW) onKey(i + 1, now);
      }
    }

    if (msgUntil && now >= msgUntil) {
      msgUntil = 0;
      digitalWrite(PIN_LED_NG, LOW);
      showInput();
    }
    if (state == OPEN && now >= stateUntil) {
      state = LOCKED;
      doorOpen = false;
      door.write(0);
      digitalWrite(PIN_LED_OK, LOW);
      logEvent("CLOSE", "auto lock");
      showInput();
    }
    if (state == LOCKOUT) {
      if (now >= stateUntil) {
        state = LOCKED;
        digitalWrite(PIN_LED_NG, LOW);
        logEvent("UNLOCK", "lockout ended");
        showInput();
      } else if (now - lastDraw > 1000) {
        lastDraw = now;
        char l1[17];
        snprintf(l1, sizeof(l1), "LOCKED %lus", (unsigned long)((stateUntil - now) / 1000 + 1));
        showLine(0, l1);
      }
    }
    vTaskDelay(pdMS_TO_TICKS(5));
  }
}

// ── sensor 작업: PIR 침입 감지 · 설비실 온습도 ───────
void checkEnvironment() {
  float t = dht.readTemperature();
  float h = dht.readHumidity();
  static bool errActive = false, hotActive = false, humidActive = false;
  char d[32];
  if (isnan(t) || isnan(h)) {
    if (!errActive) logEvent("SENSOR_ERR", "dht read failed");   // 들어갈 때 한 번
    errActive = true;
    return;
  }
  errActive = false;
  tempNow = t; humNow = h;
  bool hot = t >= ENV_HOT_C, humid = h >= ENV_HUMID_PCT;
  if (hot && !hotActive)     { snprintf(d, sizeof(d), "room %.1fC overheat", t); logEvent("ENV_HOT", d);   sound(1200, 200, 2); }
  if (humid && !humidActive) { snprintf(d, sizeof(d), "room %.0f%% humid", h);    logEvent("ENV_HUMID", d); sound(900, 200, 2); }
  hotActive = hot; humidActive = humid;
}

void sensorTask(void*) {
  bool lastMotion = false;
  uint32_t lastEnv = 0;
  for (;;) {
    if (millis() - lastEnv >= ENV_READ_MS) { lastEnv = millis(); checkEnvironment(); }
    bool motion = digitalRead(PIN_PIR) == HIGH;
    if (motion && !lastMotion) {           // 움직임이 새로 시작될 때 한 번 판단
      uint32_t now = millis(), auth = lastAuthAt;
      bool authorized = doorOpen || (auth != 0 && now - auth <= AUTH_GRACE_MS);
      if (authorized) {
        logEvent("MOTION", "after pin auth");
      } else {
        logEvent("INTRUSION", "motion without pin auth");
        sound(2500, 200, 5);
      }
    }
    lastMotion = motion;
    vTaskDelay(pdMS_TO_TICKS(100));
  }
}

// ── net 작업: 사건 전송 ──────────────────────────────
void netTask(void*) {
  Event e;
  for (;;) {
    if (xQueueReceive(eventQ, &e, portMAX_DELAY) == pdTRUE) fakeNetworkSend();
  }
}

// ── console 작업 ─────────────────────────────────────
void consoleTask(void*) {
  uint32_t lastStat = millis();
  String buf;
  for (;;) {
    while (Serial.available()) {
      char c = Serial.read();
      if (c == '\n' || c == '\r') {
        buf.trim();
        if (buf == "log") printLog();
        else if (buf == "stat") printStat();
        buf = "";
      } else if (buf.length() < 32) {
        buf += c;
      }
    }
    if (millis() - lastStat >= STAT_EVERY_MS) { lastStat = millis(); printStat(); }
    vTaskDelay(pdMS_TO_TICKS(20));
  }
}

// ── 시작 ─────────────────────────────────────────────
void setup() {
  Serial.begin(115200);
  for (int i = 0; i < 4; i++) pinMode(BTN_PINS[i], INPUT_PULLUP);
  pinMode(PIN_BUZZER, OUTPUT);
  pinMode(PIN_TRIG, OUTPUT);
  pinMode(PIN_ECHO, INPUT);
  pinMode(PIN_PIR, INPUT);
  pinMode(PIN_PUMP, OUTPUT);
  pinMode(PIN_LED_OK, OUTPUT);
  pinMode(PIN_LED_NG, OUTPUT);
  door.attach(PIN_DOOR);
  valve.attach(PIN_VALVE);
  door.write(0);
  valve.write(0);
  analogSetPinAttenuation(PIN_LM35, ADC_11db);   // 0~3.3V 범위로 읽기
  dht.begin();
  Wire.begin(21, 22);
  lcd.init();
  lcd.backlight();

  eventQ   = xQueueCreate(20, sizeof(Event));
  soundQ   = xQueueCreate(8, sizeof(Sound));
  lcdMutex = xSemaphoreCreateMutex();
  logMutex = xSemaphoreCreateMutex();

  logEvent("BOOT", NET_IN_LOOP ? "mode net_in_loop" : "mode tasks");
  Serial.println("시리얼 명령: log = 사고 기록 전체 · stat = 지금 측정값 (10초마다 자동)");

  // 전부 코어 1 — 한 코어를 우선순위로 나눠 쓰는 걸 보이려고
  xTaskCreatePinnedToCore(processTask, "process", 4096, nullptr, 4, &hProcess, 1);
  xTaskCreatePinnedToCore(inputTask,   "input",   4096, nullptr, 3, &hInput,   1);
  xTaskCreatePinnedToCore(soundTask,   "sound",   2048, nullptr, 3, &hSound,   1);
  xTaskCreatePinnedToCore(sensorTask,  "sensor",  3072, nullptr, 2, &hSensor,  1);
  xTaskCreatePinnedToCore(netTask,     "net",     4096, nullptr, 1, &hNet,     1);
  xTaskCreatePinnedToCore(consoleTask, "console", 4096, nullptr, 1, &hConsole, 1);
}

void loop() {
  vTaskDelete(nullptr);                    // Arduino 기본 loop 작업은 쓰지 않음
}
