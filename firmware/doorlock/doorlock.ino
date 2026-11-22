// 스마트 도어락 — 1단계 뼈대 (Wokwi · ESP32)
//
//  버튼 4개(1~4)로 비밀번호 4자리 입력 → 맞으면 서보로 문 열림
//  레이트 리밋: 60초 안에 5번 틀리면 30초 잠금 + 부저 경보 (잠금이 반복되면 시간 2배)
//  배회 감지: 초음파로 문 앞 50cm 안에 10초 넘게 있는데 입력이 없으면 기록
//  사고 기록: 모든 사건을 메모리에 남기고 시리얼로 한 줄씩 출력 (2단계에서 AI 리포트 · 3단계에서 서명에 씀)
//
//  수업 연결: 스위치(4주차, 풀업) · 부저(5주차) · 서보(8주차) · 시리얼(10주차) · LCD(12주차) · 초음파(13주차)

#include <Wire.h>
#include <LiquidCrystal_I2C.h>
#include <ESP32Servo.h>

// ── 핀 ───────────────────────────────────────────────
const int BTN_PINS[4] = {13, 12, 14, 27};   // 버튼 1·2·3·4 (다른 쪽은 GND, 내부 풀업 사용)
const int PIN_SERVO   = 18;
const int PIN_BUZZER  = 19;
const int PIN_TRIG    = 5;
const int PIN_ECHO    = 17;
const int PIN_LED_OK  = 25;                 // 초록: 열림
const int PIN_LED_NG  = 26;                 // 빨강: 틀림 · 잠금

// ── 설정 ─────────────────────────────────────────────
const char PASSWORD[5]            = "2413"; // 비밀번호 (버튼 번호)
const int  PW_LEN                 = 4;
const unsigned long OPEN_MS       = 5000;   // 문 열려 있는 시간
const int  FAIL_LIMIT             = 5;      // 레이트 리밋: 이 횟수만큼
const unsigned long FAIL_WINDOW   = 60000;  //   이 시간 안에 틀리면
const unsigned long LOCKOUT_BASE  = 30000;  //   이만큼 잠금 (반복될수록 2배)
const int  LOITER_CM              = 50;     // 배회: 이 거리 안에
const unsigned long LOITER_MS     = 10000;  //   이 시간 넘게 입력 없이 있으면
const unsigned long DEBOUNCE_MS   = 40;

LiquidCrystal_I2C lcd(0x27, 16, 2);
Servo door;

// ── 상태 ─────────────────────────────────────────────
enum State { LOCKED, OPEN, LOCKOUT };
State state = LOCKED;
unsigned long stateUntil = 0;               // OPEN · LOCKOUT 이 끝나는 시각

char input[PW_LEN + 1] = "";
int  inputLen = 0;

unsigned long failTimes[FAIL_LIMIT];        // 최근 실패 시각 (원형 버퍼)
int  failIdx = 0, failCount = 0;
int  lockoutCount = 0;                      // 잠금 몇 번째인지 (시간 2배용)

bool btnLast[4] = {HIGH, HIGH, HIGH, HIGH};
unsigned long btnChanged[4] = {0, 0, 0, 0};

unsigned long presenceSince = 0;            // 문 앞에 사람이 처음 감지된 시각 (0 = 없음)
unsigned long lastKeyAt = 0;
bool loiterLogged = false;

// ── 사고 기록 ────────────────────────────────────────
struct Event { unsigned long ms; char type[12]; char detail[32]; };
const int LOG_MAX = 50;
Event logBuf[LOG_MAX];
int logCount = 0;                           // 가득 차면 오래된 것부터 덮어씀
int logHead = 0;

void logEvent(const char* type, const char* detail) {
  Event& e = logBuf[logHead];
  e.ms = millis();
  strncpy(e.type, type, sizeof(e.type) - 1);     e.type[sizeof(e.type) - 1] = '\0';
  strncpy(e.detail, detail, sizeof(e.detail) - 1); e.detail[sizeof(e.detail) - 1] = '\0';
  logHead = (logHead + 1) % LOG_MAX;
  if (logCount < LOG_MAX) logCount++;
  // 한 줄 JSON — 나중에 AI 에 그대로 넘긴다
  Serial.printf("EVENT {\"t\":%lu,\"type\":\"%s\",\"detail\":\"%s\"}\n", e.ms / 1000, e.type, e.detail);
}

void printLog() {                           // 시리얼에 "log" 입력하면 전체 출력
  Serial.printf("=== 사고 기록 %d건 ===\n", logCount);
  int start = (logHead - logCount + LOG_MAX) % LOG_MAX;
  for (int i = 0; i < logCount; i++) {
    const Event& e = logBuf[(start + i) % LOG_MAX];
    Serial.printf("T+%02lu:%02lu  %-10s %s\n", e.ms / 60000, (e.ms / 1000) % 60, e.type, e.detail);
  }
}

// ── 화면 · 소리 ──────────────────────────────────────
void show(const char* line1, const char* line2) {
  lcd.clear();
  lcd.setCursor(0, 0); lcd.print(line1);
  lcd.setCursor(0, 1); lcd.print(line2);
}

void showInput() {
  char stars[PW_LEN + 1];
  for (int i = 0; i < PW_LEN; i++) stars[i] = (i < inputLen) ? '*' : '_';   // 비밀번호는 화면에 안 보이게
  stars[PW_LEN] = '\0';
  char l2[17];
  snprintf(l2, sizeof(l2), "PW: %s", stars);
  show("Enter password", l2);
}

void beep(int freq, int ms) { tone(PIN_BUZZER, freq, ms); }

// ── 비밀번호 확인 ────────────────────────────────────
bool checkPassword() {
  // 끝까지 다 비교한다 (앞자리에서 바로 멈추면 응답 시간 차이로 자릿수를 추측할 수 있음)
  int diff = 0;
  for (int i = 0; i < PW_LEN; i++) diff |= (input[i] ^ PASSWORD[i]);
  return diff == 0;
}

int recentFailures(unsigned long now) {     // FAIL_WINDOW 안의 실패 수
  int n = 0;
  for (int i = 0; i < failCount; i++)
    if (now - failTimes[i] <= FAIL_WINDOW) n++;
  return n;
}

void onWrongPassword(unsigned long now) {
  failTimes[failIdx] = now;
  failIdx = (failIdx + 1) % FAIL_LIMIT;
  if (failCount < FAIL_LIMIT) failCount++;

  int n = recentFailures(now);
  char d[32];
  snprintf(d, sizeof(d), "%d/%d in 60s", n, FAIL_LIMIT);
  logEvent("FAIL", d);
  digitalWrite(PIN_LED_NG, HIGH);
  beep(300, 300);

  if (n >= FAIL_LIMIT) {                    // 레이트 리밋 초과 → 잠금
    unsigned long dur = LOCKOUT_BASE << min(lockoutCount, 4);   // 30s, 60s, 120s ... 최대 8분
    lockoutCount++;
    state = LOCKOUT;
    stateUntil = now + dur;
    failCount = 0; failIdx = 0;             // 잠금 뒤에는 새로 셈
    snprintf(d, sizeof(d), "#%d %lus", lockoutCount, dur / 1000);
    logEvent("LOCKOUT", d);
    for (int i = 0; i < 3; i++) { beep(1000, 150); delay(200); }   // 경보
  } else {
    char l2[17];
    snprintf(l2, sizeof(l2), "Wrong %d/%d", n, FAIL_LIMIT);
    show("Access denied", l2);
    delay(800);
    digitalWrite(PIN_LED_NG, LOW);
    showInput();
  }
}

void onKey(int key, unsigned long now) {    // key = 1..4
  lastKeyAt = now;
  if (state == LOCKOUT) {                   // 잠금 중 입력도 기록 (계속 시도하는 것 자체가 신호)
    logEvent("KEY_LOCKED", "input during lockout");
    beep(200, 80);
    return;
  }
  if (state == OPEN) return;

  beep(1500, 30);
  input[inputLen++] = '0' + key;
  input[inputLen] = '\0';
  showInput();

  if (inputLen == PW_LEN) {
    if (checkPassword()) {
      state = OPEN;
      stateUntil = now + OPEN_MS;
      failCount = 0; failIdx = 0;
      logEvent("OPEN", "password ok");
      door.write(90);
      digitalWrite(PIN_LED_OK, HIGH);
      beep(2000, 100);
      show("Door OPEN", "Welcome");
    } else {
      onWrongPassword(now);
    }
    inputLen = 0; input[0] = '\0';
  }
}

// ── 초음파 ───────────────────────────────────────────
long readDistanceCm() {
  digitalWrite(PIN_TRIG, LOW);  delayMicroseconds(2);
  digitalWrite(PIN_TRIG, HIGH); delayMicroseconds(10);
  digitalWrite(PIN_TRIG, LOW);
  long us = pulseIn(PIN_ECHO, HIGH, 30000);   // 30ms 넘으면 0 (감지 없음)
  return us == 0 ? 999 : us / 58;
}

void checkLoitering(unsigned long now) {
  static unsigned long lastRead = 0;
  if (now - lastRead < 200) return;         // 0.2초마다
  lastRead = now;

  long cm = readDistanceCm();
  if (cm <= LOITER_CM) {
    if (presenceSince == 0) { presenceSince = now; loiterLogged = false; }
    bool noInput = (lastKeyAt < presenceSince) || (now - lastKeyAt > LOITER_MS);
    if (!loiterLogged && noInput && now - presenceSince > LOITER_MS) {
      char d[32];
      snprintf(d, sizeof(d), "%ldcm %lus no input", cm, (now - presenceSince) / 1000);
      logEvent("LOITER", d);
      loiterLogged = true;                  // 한 번 머무는 동안 한 번만
      beep(600, 200);
    }
  } else {
    presenceSince = 0;
  }
}

// ── 시작 · 반복 ──────────────────────────────────────
void setup() {
  Serial.begin(115200);
  for (int i = 0; i < 4; i++) pinMode(BTN_PINS[i], INPUT_PULLUP);
  pinMode(PIN_BUZZER, OUTPUT);
  pinMode(PIN_TRIG, OUTPUT);
  pinMode(PIN_ECHO, INPUT);
  pinMode(PIN_LED_OK, OUTPUT);
  pinMode(PIN_LED_NG, OUTPUT);

  door.attach(PIN_SERVO);
  door.write(0);                            // 0도 = 잠김

  Wire.begin(21, 22);
  lcd.init();
  lcd.backlight();

  logEvent("BOOT", "door locked");
  Serial.println("시리얼에 log 를 입력하면 사고 기록 전체를 출력합니다.");
  showInput();
}

void loop() {
  unsigned long now = millis();

  // 버튼 (풀업이라 눌리면 LOW)
  for (int i = 0; i < 4; i++) {
    bool v = digitalRead(BTN_PINS[i]);
    if (v != btnLast[i] && now - btnChanged[i] > DEBOUNCE_MS) {
      btnChanged[i] = now;
      btnLast[i] = v;
      if (v == LOW) onKey(i + 1, now);
    }
  }

  // 상태 시간 끝
  if (state == OPEN && now >= stateUntil) {
    state = LOCKED;
    door.write(0);
    digitalWrite(PIN_LED_OK, LOW);
    logEvent("CLOSE", "auto lock");
    showInput();
  }
  if (state == LOCKOUT) {
    static unsigned long lastDraw = 0;
    if (now >= stateUntil) {
      state = LOCKED;
      digitalWrite(PIN_LED_NG, LOW);
      logEvent("UNLOCK", "lockout ended");
      showInput();
    } else if (now - lastDraw > 1000) {     // 남은 시간 표시
      lastDraw = now;
      char l2[17];
      snprintf(l2, sizeof(l2), "Wait %lus", (stateUntil - now) / 1000 + 1);
      show("LOCKED: too many", l2);
    }
  }

  checkLoitering(now);

  // 시리얼 명령
  if (Serial.available()) {
    String cmd = Serial.readStringUntil('\n');
    cmd.trim();
    if (cmd == "log") printLog();
  }
}
