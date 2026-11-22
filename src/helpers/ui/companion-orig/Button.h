#pragma once

#include <Arduino.h>
#include <functional>

// Button timing configuration
#define BUTTON_DEBOUNCE_TIME_MS    30      // after a change is taken, further edges are bounce for this long
#define BUTTON_MIN_PRESS_MS        8       // shorter presses are noise: no click, no feedback
#define BUTTON_CLICK_TIMEOUT_MS    500     // Max time between clicks for multi-click
#define BUTTON_LONG_PRESS_TIME_MS  3000    // Time to trigger long press (3 seconds)
#define BUTTON_READ_INTERVAL_MS    10      // How often to read an analog button
#define BUTTON_EDGE_QUEUE          16      // edges kept between two update() calls

// A digital button is read by a pin-change interrupt that stamps each edge with its time; update() works
// through those edges in order, so presses and the gaps between clicks are measured from the edges, not
// from when the main loop got round to looking. A loop held up for a while loses nothing. An analog
// button is still polled.
class Button {
public:
    enum EventType {
        NONE,
        SHORT_PRESS,
        DOUBLE_PRESS,
        TRIPLE_PRESS,
        QUADRUPLE_PRESS,
        QUINTUPLE_PRESS,   // five or more
        LONG_PRESS,
        ANY_PRESS
    };

    using EventCallback = std::function<void()>;

    Button(uint8_t pin, bool activeState = LOW);
    Button(uint8_t pin, bool activeState, bool isAnalog, uint16_t analogThreshold = 20);

    void begin();
    void update();

    // Set callbacks for different events
    void onShortPress(EventCallback callback) { _onShortPress = callback; }
    void onDoublePress(EventCallback callback) { _onDoublePress = callback; }
    void onTriplePress(EventCallback callback) { _onTriplePress = callback; }
    void onQuadruplePress(EventCallback callback) { _onQuadruplePress = callback; }
    void onQuintuplePress(EventCallback callback) { _onQuintuplePress = callback; }
    void onLongPress(EventCallback callback) { _onLongPress = callback; }
    void onAnyPress(EventCallback callback) { _onAnyPress = callback; }   // each press, as soon as it counts

    // State getters
    bool isPressed() const { return _currentState; }
    EventType getLastEvent() const { return _lastEvent; }

private:
    enum State {
        IDLE,
        PRESSED,
        RELEASED,
        WAITING_FOR_MULTI_CLICK
    };

    uint8_t _pin;
    bool _activeState;
    bool _isAnalog;
    uint16_t _analogThreshold;

    State _state = IDLE;
    bool _currentState;         // debounced: pressed or not
    bool _confirmed = false;    // the current press has lasted BUTTON_MIN_PRESS_MS
    bool _rawPressed = false;   // the pin's level at the latest edge (or read)

    uint32_t _changeTime = 0;   // when _currentState last changed
    uint32_t _pressTime = 0;
    uint32_t _releaseTime = 0;
    uint32_t _lastReadTime = 0;

    uint8_t _clickCount = 0;
    EventType _lastEvent = NONE;

    // edges from the interrupt: time and pressed/released, read in order by update()
    struct Edge { uint32_t ms; bool pressed; };
    volatile Edge _edges[BUTTON_EDGE_QUEUE];
    volatile uint8_t _head = 0, _tail = 0;
    volatile bool _overflow = false;
    bool _useIrq = false;
    uint32_t _lastRawMs = 0;    // the latest edge seen, taken or not

    // Callbacks
    EventCallback _onShortPress = nullptr;
    EventCallback _onDoublePress = nullptr;
    EventCallback _onTriplePress = nullptr;
    EventCallback _onQuadruplePress = nullptr;
    EventCallback _onQuintuplePress = nullptr;
    EventCallback _onLongPress = nullptr;
    EventCallback _onAnyPress = nullptr;

    bool readButton();
    void edge(bool pressed, uint32_t ms);     // a raw edge, debounced here
    void change(bool pressed, uint32_t ms);   // a debounced change
    void tick(uint32_t now);                  // timeouts: press confirmed, long press, multi-click done
    void finishClicks();
    void triggerEvent(EventType event);

public:
    void onEdge();   // called from the pin interrupt
};
