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
//   sensor  우선순위 2  PIR 침입 감지
//   env     우선순위 1  설비실 온습도(DHT: 40°C↑ 과열 · 85%↑ 결로/침수) — **코어 0** (읽는 동안 인터럽트를 막아서)
//   net     우선순위 1  사건 전송 — secrets.h 가 있으면 실제 전송(Wi-Fi · NTP · HMAC 서명 · HTTPS), 없으면 2초 가짜 전송
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

// 3단계: secrets.h(provision.py 가 만듦 · git 에 안 올라감)가 있으면 서버로 실제 전송.
// 없으면 2초 가짜 전송 — 비밀값 없이도 2단계 실험은 그대로 돈다. NET_IN_LOOP 1 비교 모드도 가짜 전송을 쓴다
// (제어 작업 스택 3~4KB 로는 TLS 가 안 돌아서 — 대신 실제 전송 시간을 STAT net_last_ms 로 재서 2초와 비교).
#if __has_include("secrets.h") && !NET_IN_LOOP
#define NET_REAL 1
#include "secrets.h"
#include "ca_roots.h"
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <time.h>
#include "mbedtls/md.h"
#else
#define NET_REAL 0
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
const uint32_t JUMP_WINDOW_MS = 10000;     // 급변은 첫 건만 바로, 이 시간 동안은 묶어서 한 줄
const int ALARM_DEADBAND = 5;              // 경보 해제는 기준에서 이만큼(cm) 되돌아와야
const uint32_t PROCESS_MS = 200;
const float MOTOR_HOT_C   = 70.0;          // 인터록: 펌프 모터가 이 위면 펌프 강제 정지
const float MOTOR_RESET_C = 60.0;          //   이 아래로 식어야 다시 돌 수 있음 (히스테리시스)

// ── 설비실 환경 설정 ─────────────────────────────────
const float ENV_HOT_C      = 40.0;         // 이 위면 설비(펌프 · 제어반) 과열 위험
const float ENV_HUMID_PCT  = 85.0;         // 이 위면 결로 · 침수 의심
const uint32_t ENV_READ_MS = 2000;         // DHT22 는 2초, DHT11 은 1초에 한 번까지

const uint32_t FAKE_NET_MS   = 2000;
const int      NET_BATCH_MAX = 10;         // 한 번에 보내는 사건 수 (서버 최대 50 · 본문 8KB)
const uint32_t NET_BACKOFF_MAX_MS = 30000; // 실패하면 1초 → 2초 → … 30초까지 늘려 다시
const uint32_t STAT_EVERY_MS = 10000;

LiquidCrystal_I2C lcd(0x27, 16, 2);
Servo door, valve;
DHT dht(PIN_DHT, DHT_TYPE);

// ── 작업 사이 통로 ───────────────────────────────────
struct Event { uint32_t ms; char type[12]; char detail[32]; };
struct Sound { uint16_t freq; uint16_t ms; uint8_t count; };

QueueHandle_t eventQ, soundQ;
SemaphoreHandle_t lcdMutex, logMutex;
TaskHandle_t hProcess, hInput, hSound, hSensor, hNet, hConsole, hEnv;

volatile uint32_t lastAuthAt = 0;          // input 이 쓰고 sensor 가 읽음 (0 = 아직 없음)
volatile bool     doorOpen   = false;
volatile uint32_t gapInputUs = 0, gapProcessUs = 0;
volatile uint32_t netSent    = 0;         // 서버가 받은 사건 수 (가짜 전송이면 보낸 횟수)
volatile uint32_t netFail    = 0;          // 실패한 전송 시도 수
volatile uint32_t netLastMs  = 0;          // 마지막 전송에 걸린 시간 (TLS 연결 포함)
volatile int      netLastStatus = 0;       // 마지막 HTTP 상태 (음수 = 연결 실패)
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
                " stack_free_B process=%u input=%u sound=%u sensor=%u net=%u console=%u env=%u"
                " heap_free_B=%u net=%s net_sent=%u net_fail=%u net_last_ms=%u net_status=%d net_queue=%u\n",
                NET_IN_LOOP ? "net_in_loop" : "tasks", gp / 1000.0, gi / 1000.0, levelNow, motorNow, tempNow, humNow,
                (unsigned)uxTaskGetStackHighWaterMark(hProcess), (unsigned)uxTaskGetStackHighWaterMark(hInput),
                (unsigned)uxTaskGetStackHighWaterMark(hSound), (unsigned)uxTaskGetStackHighWaterMark(hSensor),
                (unsigned)uxTaskGetStackHighWaterMark(hNet), (unsigned)uxTaskGetStackHighWaterMark(hConsole), (unsigned)uxTaskGetStackHighWaterMark(hEnv),
                (unsigned)ESP.getFreeHeap(), NET_REAL ? "real" : "fake", (unsigned)netSent, (unsigned)netFail,
                (unsigned)netLastMs, netLastStatus, (unsigned)uxQueueMessagesWaiting(eventQ));
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
  uint32_t jumpWindowStart = 0;            // 급변 묶음: 첫 급변은 바로, 이후 JUMP_WINDOW_MS 동안은 세기만
  int jumpCount = 0, jumpMaxRate = 0;
  char lastLine[17] = "";                  // LCD 2줄 — 바뀔 때만 쓴다
  int64_t lastIter = esp_timer_get_time();
  TickType_t lastWake = xTaskGetTickCount();
  char d[32];

  for (;;) {
    trackGap(gapProcessUs, lastIter);
    uint32_t now = millis();
    long dist = readDistanceCm();

    if (dist < 0) {
      if (!sensorErr) {                    // 들어갈 때 한 번
        logEvent("SENSOR_ERR", "level sensor no echo");
        showLine(1, "LEVEL SENSOR ERR");
        lastLine[0] = '\0';                // 회복하면 2줄을 다시 쓰게
      }
      sensorErr = true;
      digitalWrite(PIN_PUMP, LOW);         // 안전 쪽으로: 수위를 모르면 펌프를 끈다 (넘침 방지)
    } else {
      sensorErr = false;
      int level = constrain(TANK_CM - (int)dist, 0, TANK_CM);
      levelNow = level;

      // 변화 속도 — 물리적으로 불가능하게 빠르면 센서 조작 · 누수 의심.
      // Wokwi 실측: 슬라이더를 끌면 몇 초에 급변 수십 건 → 전송 큐(20칸)가 차서 다른 사건까지 못 보냈다.
      // 그래서 첫 급변만 바로 기록하고, 이후 10초는 세기만 하다가 묶어서 한 줄 (경보 묶음 · throttle)
      if (lastLevel >= 0 && now > lastLevelAt) {
        int rate = abs(level - lastLevel) * 1000 / (int)(now - lastLevelAt);
        if (rate > JUMP_CM_PER_S) {
          if (jumpWindowStart == 0) {
            snprintf(d, sizeof(d), "%d->%dcm %dcm/s", lastLevel, level, rate);
            logEvent("LEVEL_JUMP", d);
            jumpWindowStart = now; jumpCount = 0; jumpMaxRate = 0;
          } else {
            jumpCount++;
            if (rate > jumpMaxRate) jumpMaxRate = rate;
          }
        }
      }
      if (jumpWindowStart && now - jumpWindowStart >= JUMP_WINDOW_MS) {
        if (jumpCount > 0) {
          snprintf(d, sizeof(d), "+%d in 10s max %dcm/s", jumpCount, jumpMaxRate);
          logEvent("LEVEL_JUMP", d);
        }
        jumpWindowStart = 0;
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

      // 공정 경보 — 들어갈 때 한 번, ALARM_DEADBAND 만큼 되돌아와야 해제
      // (Wokwi 실측: 190cm 언저리에서 HH 가 190 · 193 … 거듭 울렸다 — 경계에서 떨림)
      if (level >= LEVEL_HH && !hhActive) {
        snprintf(d, sizeof(d), "HH %dcm overflow risk", level);
        logEvent("ALARM", d);
        sound(1800, 300, 2);
        hhActive = true;
      } else if (hhActive && level < LEVEL_HH - ALARM_DEADBAND) {
        hhActive = false;
      }
      if (level <= LEVEL_LL && !llActive) {
        snprintf(d, sizeof(d), "LL %dcm tank low", level);
        logEvent("ALARM", d);
        sound(500, 300, 2);
        llActive = true;
      } else if (llActive && level > LEVEL_LL + ALARM_DEADBAND) {
        llActive = false;
      }

      // LCD 는 I2C 라 느리다 — 0.2초마다 다시 쓰면 공정 작업 주기가 늘고(실측 256ms) 입력 작업이 LCD 를 기다린다
      char l2[17];
      snprintf(l2, sizeof(l2), "L%3d V%s P%s", level, valveOpen ? "OPN" : "SHT",
               interlock ? "IL" : (pumpOn ? "ON" : "OF"));       // IL = 인터록으로 정지
      if (strcmp(l2, lastLine) != 0) {
        showLine(1, l2);
        strlcpy(lastLine, l2, sizeof(lastLine));
      }
    }
    // 고정 주기: vTaskDelay(200) 은 "일한 뒤 200ms 쉼"이라 주기 = 200 + 일한 시간 (Wokwi 실측 256~261ms).
    // vTaskDelayUntil 은 "지난번 깨어난 때부터 200ms" — 일이 200ms 안에 끝나면 주기가 정확히 200ms
    vTaskDelayUntil(&lastWake, pdMS_TO_TICKS(PROCESS_MS));
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

// ── env 작업 (코어 0): 설비실 온습도 ─────────────────
// DHT 는 마이크로초 단위 타이밍으로 읽어서, 읽는 동안 라이브러리가 인터럽트를 막는다. 처음에는 sensor 작업(코어 1)에서
// 읽었더니 Wokwi 실측에서 ① 읽기가 8초마다 실패하고 ② 같은 코어의 공정 작업이 최대 0.41초(원래 0.2초 주기),
// 입력 작업이 0.16초(원래 0.005초) 멈췄다. 그래서 제어 작업이 없는 코어 0 의 따로 작업으로 옮겼다.
// 3단계 Wi-Fi 도 코어 0 에서 돌아서, 그때 다시 잰다.
const int DHT_FAIL_LOG_AFTER = 3;          // 연속 실패가 이만큼일 때만 SENSOR_ERR (한두 번은 흔하다)

void checkEnvironment() {
  float t = dht.readTemperature();
  float h = dht.readHumidity();
  static int fails = 0;
  static bool errActive = false, hotActive = false, humidActive = false;
  char d[32];
  if (isnan(t) || isnan(h)) {
    fails++;
    if (fails == DHT_FAIL_LOG_AFTER) {
      snprintf(d, sizeof(d), "dht %d reads failed", fails);
      logEvent("SENSOR_ERR", d);
      errActive = true;
    }
    return;
  }
  if (errActive) logEvent("SENSOR_OK", "dht recovered");
  fails = 0;
  errActive = false;
  tempNow = t; humNow = h;
  bool hot = t >= ENV_HOT_C, humid = h >= ENV_HUMID_PCT;
  if (hot && !hotActive)     { snprintf(d, sizeof(d), "room %.1fC overheat", t); logEvent("ENV_HOT", d);   sound(1200, 200, 2); }
  if (humid && !humidActive) { snprintf(d, sizeof(d), "room %.0f%% humid", h);    logEvent("ENV_HUMID", d); sound(900, 200, 2); }
  hotActive = hot; humidActive = humid;
}

void envTask(void*) {
  for (;;) {
    checkEnvironment();
    vTaskDelay(pdMS_TO_TICKS(ENV_READ_MS));
  }
}

// ── sensor 작업: PIR 침입 감지 ───────────────────────
void sensorTask(void*) {
  bool lastMotion = false;
  for (;;) {
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
#if NET_REAL
// 서버 계약 (server/app/security.py):
//   POST {SERVER_URL}/api/v1/sites/{SITE_ID}/events   본문 {"events":[{"t","type","detail"}, ...]}
//   Authorization: Bearer 토큰 · X-Timestamp: 유닉스 초 · X-Seq: 계속 커지는 번호
//   X-Signature: hex(HMAC_SHA256(비밀, "ts\nseq\n" + 본문))
// 비밀값은 서명에만 쓰고 보내지 않는다. 서버는 시각 ±300초 · 이미 받은 번호 이하를 거부한다(다시 보내기 공격 차단).
Event netBatch[NET_BATCH_MAX];
int netBatchN = 0;
uint64_t netSeq = 0;                       // 첫 시각 맞춤 때 유닉스 초 × 1000 에서 시작 → 재부팅해도 커진다
char netBody[2048];

void netLog(const char* msg) {
  xSemaphoreTake(logMutex, portMAX_DELAY);
  Serial.println(msg);
  xSemaphoreGive(logMutex);
}

// Wi-Fi 연결 + NTP 시각 맞춤 (서명 시각이 맞아야 서버가 받는다). 둘 다 되면 true
bool netEnsure() {
  if (WiFi.status() != WL_CONNECTED) {
    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASS);
    for (int i = 0; i < 100 && WiFi.status() != WL_CONNECTED; i++) vTaskDelay(pdMS_TO_TICKS(100));
    if (WiFi.status() != WL_CONNECTED) { netLog("NET wifi 연결 실패 — 다시 시도"); return false; }
    char m[64];
    snprintf(m, sizeof(m), "NET wifi 연결 ip=%s", WiFi.localIP().toString().c_str());
    netLog(m);
    configTime(0, 0, "pool.ntp.org", "time.google.com");
  }
  for (int i = 0; i < 100 && time(nullptr) < 1700000000; i++) vTaskDelay(pdMS_TO_TICKS(100));
  if (time(nullptr) < 1700000000) { netLog("NET 시각 맞춤(NTP) 실패 — 다시 시도"); return false; }
  if (netSeq == 0) netSeq = (uint64_t)time(nullptr) * 1000ULL;
  return true;
}

// JSON 문자열 안에 넣을 수 있게 " \ 제어문자를 바꾼다
size_t jsonPut(char* out, size_t cap, size_t pos, const char* s) {
  for (; *s && pos + 7 < cap; s++) {
    unsigned char c = (unsigned char)*s;
    if (c == '"' || c == '\\') { out[pos++] = '\\'; out[pos++] = c; }
    else if (c < 0x20) pos += snprintf(out + pos, cap - pos, "\\u%04x", c);
    else out[pos++] = c;
  }
  out[pos] = 0;
  return pos;
}

// netBatch → netBody. 사건 시각은 유닉스 초로 바꿔 보낸다 (지금 시각 - 지난 시간)
size_t netBuildBody() {
  uint32_t nowMs = millis();
  time_t nowS = time(nullptr);
  size_t pos = snprintf(netBody, sizeof(netBody), "{\"events\":[");
  for (int i = 0; i < netBatchN && pos + 128 < sizeof(netBody); i++) {
    long t = (long)(nowS - (time_t)((nowMs - netBatch[i].ms) / 1000));
    pos += snprintf(netBody + pos, sizeof(netBody) - pos, "%s{\"t\":%ld,\"type\":\"", i ? "," : "", t);
    pos = jsonPut(netBody, sizeof(netBody), pos, netBatch[i].type);
    pos += snprintf(netBody + pos, sizeof(netBody) - pos, "\",\"detail\":\"");
    pos = jsonPut(netBody, sizeof(netBody), pos, netBatch[i].detail);
    pos += snprintf(netBody + pos, sizeof(netBody) - pos, "\"}");
  }
  pos += snprintf(netBody + pos, sizeof(netBody) - pos, "]}");
  return pos;
}

void hmacHex(const char* prefix, const char* body, size_t bodyLen, char* outHex) {
  uint8_t mac[32];
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
  mbedtls_md_hmac_starts(&ctx, (const unsigned char*)DEVICE_SECRET, strlen(DEVICE_SECRET));
  mbedtls_md_hmac_update(&ctx, (const unsigned char*)prefix, strlen(prefix));
  mbedtls_md_hmac_update(&ctx, (const unsigned char*)body, bodyLen);
  mbedtls_md_hmac_finish(&ctx, mac);
  mbedtls_md_free(&ctx);
  for (int i = 0; i < 32; i++) sprintf(outHex + i * 2, "%02x", mac[i]);
  outHex[64] = 0;
}

// netBatch 를 한 번 보낸다. 돌려주는 값 = HTTP 상태 (음수 = 연결 실패)
int netSendBatch() {
  size_t len = netBuildBody();
  unsigned long long seq = ++netSeq;       // 다시 보낼 때도 새 번호 · 새 시각 · 새 서명
  long ts = (long)time(nullptr);
  char prefix[48], sig[65], hdr[24];
  snprintf(prefix, sizeof(prefix), "%ld\n%llu\n", ts, seq);
  hmacHex(prefix, netBody, len, sig);

  String url = String(SERVER_URL) + "/api/v1/sites/" + SITE_ID + "/events";
  bool tls = url.startsWith("https://");
  WiFiClientSecure sec;
  WiFiClient plain;
  if (tls) sec.setCACert(CA_ROOTS);        // 루트 CA 로 서버 인증서 확인 (setInsecure 안 씀)
  HTTPClient http;
  http.setConnectTimeout(8000);
  http.setTimeout(10000);
  uint32_t t0 = millis();
  bool ok = tls ? http.begin(sec, url) : http.begin(plain, url);
  if (!ok) { netLastStatus = -100; return -100; }
  http.addHeader("Content-Type", "application/json");
  http.addHeader("Authorization", String("Bearer ") + DEVICE_TOKEN);
  snprintf(hdr, sizeof(hdr), "%ld", ts);
  http.addHeader("X-Timestamp", hdr);
  snprintf(hdr, sizeof(hdr), "%llu", seq);
  http.addHeader("X-Seq", hdr);
  http.addHeader("X-Signature", sig);
  http.setUserAgent("reservoir-rtu/3");
  int st = http.POST((uint8_t*)netBody, len);
  http.end();
  netLastMs = millis() - t0;
  netLastStatus = st;
  return st;
}

void netTask(void*) {
  uint32_t backoff = 1000;
  char m[112];
  for (;;) {
    if (netBatchN == 0) {                  // 사건이 올 때까지 기다리고, 0.3초 동안 더 온 것은 묶는다
      if (xQueueReceive(eventQ, &netBatch[0], portMAX_DELAY) != pdTRUE) continue;
      netBatchN = 1;
    }
    while (netBatchN < NET_BATCH_MAX && xQueueReceive(eventQ, &netBatch[netBatchN], pdMS_TO_TICKS(300)) == pdTRUE) netBatchN++;
    if (!netEnsure()) {
      netFail = netFail + 1;
      vTaskDelay(pdMS_TO_TICKS(backoff));
      backoff = min(backoff * 2, NET_BACKOFF_MAX_MS);
      continue;
    }

    int st = netSendBatch();
    if (st == 200) {
      netSent = netSent + netBatchN;
      snprintf(m, sizeof(m), "NET 보냄 %d건 status=200 %ums", netBatchN, (unsigned)netLastMs);
      netLog(m);
      netBatchN = 0;
      backoff = 1000;
    } else if (st == 400 || st == 403 || st == 409 || st == 413) {
      // 다시 보내도 안 되는 거절 (본문 · 사이트 · 번호) — 버리고 기록. 사건은 장치 log 에 남아 있다
      netFail = netFail + 1;
      snprintf(m, sizeof(m), "NET 거절 status=%d — 이 묶음 %d건 버림 (장치 log 에는 있음)", st, netBatchN);
      netLog(m);
      netBatchN = 0;
    } else {
      // 401(시각 · 서명) · 429(레이트 리밋) · 5xx · 연결 실패 → 묶음을 그대로 두고 점점 늦게 다시
      netFail = netFail + 1;
      snprintf(m, sizeof(m), "NET 실패 status=%d %ums — %u초 뒤 다시 (%d건 대기)", st, (unsigned)netLastMs,
               (unsigned)(backoff / 1000), netBatchN);
      netLog(m);
      if (st == 401) configTime(0, 0, "pool.ntp.org", "time.google.com");   // 시각이 틀렸을 수 있음
      vTaskDelay(pdMS_TO_TICKS(backoff));
      backoff = min(backoff * 2, NET_BACKOFF_MAX_MS);
    }
  }
}
#else
void netTask(void*) {
  Event e;
  for (;;) {
    if (xQueueReceive(eventQ, &e, portMAX_DELAY) == pdTRUE) fakeNetworkSend();
  }
}
#endif

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

  // 제어 작업은 전부 코어 1 — 한 코어를 우선순위로 나눠 쓰는 걸 보이려고. DHT 만 코어 0
  xTaskCreatePinnedToCore(processTask, "process", 4096, nullptr, 4, &hProcess, 1);
  xTaskCreatePinnedToCore(inputTask,   "input",   4096, nullptr, 3, &hInput,   1);
  xTaskCreatePinnedToCore(soundTask,   "sound",   2048, nullptr, 3, &hSound,   1);
  xTaskCreatePinnedToCore(sensorTask,  "sensor",  3072, nullptr, 2, &hSensor,  1);
  xTaskCreatePinnedToCore(netTask,     "net",     NET_REAL ? 10240 : 4096, nullptr, 1, &hNet, 1);   // TLS 는 스택을 많이 씀
  xTaskCreatePinnedToCore(consoleTask, "console", 4096, nullptr, 1, &hConsole, 1);
  xTaskCreatePinnedToCore(envTask,     "env",     3072, nullptr, 1, &hEnv,     0);   // DHT 는 코어 0 (위 설명)
}

void loop() {
  vTaskDelete(nullptr);                    // Arduino 기본 loop 작업은 쓰지 않음
}
