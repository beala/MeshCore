#include "Button.h"

#if defined(ESP32)
  #define BUTTON_ISR_ATTR IRAM_ATTR
#else
  #define BUTTON_ISR_ATTR
#endif

// attachInterrupt() takes a plain function, so each digital button gets a slot and a small function
static Button* s_buttons[2] = { nullptr, nullptr };
static void BUTTON_ISR_ATTR buttonIsr0() { if (s_buttons[0]) s_buttons[0]->onEdge(); }
static void BUTTON_ISR_ATTR buttonIsr1() { if (s_buttons[1]) s_buttons[1]->onEdge(); }

Button::Button(uint8_t pin, bool activeState)
    : _pin(pin), _activeState(activeState), _isAnalog(false), _analogThreshold(20) {
    _currentState = false;  // Initialize as not pressed
}

Button::Button(uint8_t pin, bool activeState, bool isAnalog, uint16_t analogThreshold)
    : _pin(pin), _activeState(activeState), _isAnalog(isAnalog), _analogThreshold(analogThreshold) {
    _currentState = false;  // Initialize as not pressed
}

void Button::begin() {
    _currentState = readButton();   // held at start: its release is not a click
    _rawPressed = _currentState;
    _changeTime = _lastRawMs = millis();
    if (_isAnalog) return;
    for (int i = 0; i < 2; i++) {
        if (s_buttons[i] == nullptr || s_buttons[i] == this) {
            s_buttons[i] = this;
            attachInterrupt(digitalPinToInterrupt(_pin), i == 0 ? buttonIsr0 : buttonIsr1, CHANGE);
            _useIrq = true;
            return;
        }
    }
    // more than two digital buttons: this one is polled
}

void BUTTON_ISR_ATTR Button::onEdge() {
    uint32_t ms = millis();
    bool pressed = (digitalRead(_pin) == _activeState);
    uint8_t next = (_head + 1) % BUTTON_EDGE_QUEUE;
    if (next == _tail) { _overflow = true; return; }   // a burst of bounce: update() reads the pin instead
    _edges[_head].ms = ms;
    _edges[_head].pressed = pressed;
    _head = next;
}

void Button::update() {
    uint32_t now = millis();

    if (_useIrq) {
        if (_overflow) {
            noInterrupts();
            _tail = _head;
            _overflow = false;
            interrupts();
        }
        while (_tail != _head) {
            uint32_t ms = _edges[_tail].ms;
            bool pressed = _edges[_tail].pressed;
            _tail = (_tail + 1) % BUTTON_EDGE_QUEUE;
            tick(ms);          // whatever timed out before this edge happens first
            edge(pressed, ms);
        }
    } else {
        if (now - _lastReadTime < BUTTON_READ_INTERVAL_MS) {
            tick(now);
            return;
        }
        _lastReadTime = now;
    }

    // The pin as it is now. An edge dropped as bounce can be the last one (a press shorter than the
    // debounce time, or a burst that filled the queue): once the debounce time is over, take the pin's
    // level, dated by the last edge seen.
    bool raw = readButton();
    if (raw != _rawPressed) {
        _rawPressed = raw;
        _lastRawMs = now;
    }
    if (raw != _currentState && (int32_t)(now - _changeTime) >= BUTTON_DEBOUNCE_TIME_MS) {
        uint32_t at = ((int32_t)(_lastRawMs - _changeTime) >= 0) ? _lastRawMs : now;
        tick(at);
        change(raw, at);
    }
    tick(now);
}

bool Button::readButton() {
    if (_isAnalog) {
        return (analogRead(_pin) < _analogThreshold);
    } else {
        return (digitalRead(_pin) == _activeState);
    }
}

// A raw edge: the first one after a quiet spell is taken at once, the bounce after it ignored.
void Button::edge(bool pressed, uint32_t ms) {
    _rawPressed = pressed;
    _lastRawMs = ms;
    if (pressed == _currentState) return;
    if ((int32_t)(ms - _changeTime) < BUTTON_DEBOUNCE_TIME_MS) return;
    change(pressed, ms);
}

void Button::change(bool pressed, uint32_t ms) {
    _currentState = pressed;
    _changeTime = ms;

    if (pressed) {
        _pressTime = ms;
        _confirmed = false;
        _state = PRESSED;
        return;
    }

    if (_state != PRESSED) return;   // released after a long press, or held since start
    if (!_confirmed) {               // too short to be a press: noise, nothing counted
        _state = _clickCount ? WAITING_FOR_MULTI_CLICK : IDLE;
        return;
    }
    _clickCount++;
    _releaseTime = ms;
    _state = WAITING_FOR_MULTI_CLICK;
}

void Button::tick(uint32_t now) {
    if (_state == PRESSED && _currentState) {
        int32_t held = (int32_t)(now - _pressTime);
        if (!_confirmed && _rawPressed && held >= BUTTON_MIN_PRESS_MS) {
            _confirmed = true;
            triggerEvent(ANY_PRESS);
        }
        if (_confirmed && held > BUTTON_LONG_PRESS_TIME_MS) {
            triggerEvent(LONG_PRESS);
            _state = IDLE;  // Prevent multiple press events
            _clickCount = 0;
        }
    }
    if (_state == WAITING_FOR_MULTI_CLICK && (int32_t)(now - _releaseTime) > BUTTON_CLICK_TIMEOUT_MS) {
        finishClicks();
    }
}

void Button::finishClicks() {
    if (_clickCount == 1) {
        triggerEvent(SHORT_PRESS);
    } else if (_clickCount == 2) {
        triggerEvent(DOUBLE_PRESS);
    } else if (_clickCount == 3) {
        triggerEvent(TRIPLE_PRESS);
    } else if (_clickCount == 4) {
        triggerEvent(QUADRUPLE_PRESS);
    } else if (_clickCount >= 5) {
        triggerEvent(QUINTUPLE_PRESS);
    }
    _clickCount = 0;
    _state = IDLE;
}

void Button::triggerEvent(EventType event) {
    _lastEvent = event;

    switch (event) {
        case ANY_PRESS:
            if (_onAnyPress) _onAnyPress();
            break;
        case SHORT_PRESS:
            if (_onShortPress) _onShortPress();
            break;
        case DOUBLE_PRESS:
            if (_onDoublePress) _onDoublePress();
            break;
        case TRIPLE_PRESS:
            if (_onTriplePress) _onTriplePress();
            break;
        case QUADRUPLE_PRESS:
            if (_onQuadruplePress) _onQuadruplePress();
            break;
        case QUINTUPLE_PRESS:
            if (_onQuintuplePress) _onQuintuplePress();
            break;
        case LONG_PRESS:
            if (_onLongPress) _onLongPress();
            break;
        default:
            break;
    }
}
