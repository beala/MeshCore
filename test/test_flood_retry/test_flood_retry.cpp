#include <gtest/gtest.h>
#include "FloodRetry.h"

using namespace mesh;

// A channel message as it leaves the sender (flood, no hops yet).
static Packet makeFlood(uint8_t seed, uint8_t hops = 0) {
  Packet p;
  p.header = ROUTE_TYPE_FLOOD | (PAYLOAD_TYPE_GRP_TXT << PH_TYPE_SHIFT);
  for (int i = 0; i < 20; i++) p.payload[i] = seed + i;
  p.payload_len = 20;
  p.setPathHashSizeAndCount(1, 0);
  for (int i = 0; i < hops; i++) p.path[i] = 0xA0 + i;
  p.setPathHashCount(hops);
  return p;
}

// The same packet after hops more repeaters passed it on.
static Packet repeated(const Packet& p, uint8_t extra_hops) {
  Packet q = p;
  uint8_t n = q.getPathHashCount();
  for (int i = 0; i < extra_hops; i++) q.path[n + i] = 0xB0 + i;
  q.setPathHashCount(n + extra_hops);
  return q;
}

static const uint32_t WAIT = 2000;

TEST(FloodRetry, EchoHeard_NoResend) {
  FloodRetry r;
  Packet p = makeFlood(1);
  ASSERT_TRUE(r.track(&p, 1000, 1, WAIT));
  Packet echo = repeated(p, 1);
  EXPECT_EQ(r.onHeard(&echo), FloodRetry::ECHO_HEARD);
  uint8_t raw[MAX_TRANS_UNIT]; uint8_t len;
  EXPECT_EQ(r.nextDue(1000 + 10 * WAIT, raw, len), -1);
  EXPECT_EQ(r.getActiveCount(), 0);
  EXPECT_EQ(r.getStats().echoed, 1u);
  EXPECT_EQ(r.getStats().retries, 0u);
}

TEST(FloodRetry, NoEcho_ResendsSameBytes) {
  FloodRetry r;
  Packet p = makeFlood(2);
  uint8_t orig[MAX_TRANS_UNIT];
  uint8_t orig_len = p.writeTo(orig);
  ASSERT_TRUE(r.track(&p, 1000, 1, WAIT));

  uint8_t raw[MAX_TRANS_UNIT]; uint8_t len;
  EXPECT_EQ(r.nextDue(1000 + WAIT - 1, raw, len), -1);   // not yet
  int idx = r.nextDue(1000 + WAIT, raw, len);
  ASSERT_GE(idx, 0);
  ASSERT_EQ(len, orig_len);
  EXPECT_EQ(memcmp(raw, orig, len), 0);
  EXPECT_EQ(r.nextDue(1000 + WAIT + 1, raw, len), -1);   // only once while queued
}

TEST(FloodRetry, ResendIsNotTrackedAsNewPacket) {
  FloodRetry r;
  Packet p = makeFlood(3);
  r.track(&p, 0, 1, WAIT);
  uint8_t raw[MAX_TRANS_UNIT]; uint8_t len;
  ASSERT_GE(r.nextDue(WAIT, raw, len), 0);
  Packet resend; resend.readFrom(raw, len);
  EXPECT_TRUE(r.onSent(&resend, WAIT + 100));            // recognised as our resend
  EXPECT_EQ(r.getStats().retries, 1u);
  EXPECT_EQ(r.getStats().tracked, 1u);

  // no echo after the last resend: give up
  EXPECT_EQ(r.nextDue(WAIT + 100 + WAIT, raw, len), -1);
  EXPECT_EQ(r.getActiveCount(), 0);
  EXPECT_EQ(r.getStats().gave_up, 1u);
}

TEST(FloodRetry, EchoAfterResend_Counted) {
  FloodRetry r;
  Packet p = makeFlood(4);
  r.track(&p, 0, 2, WAIT);
  uint8_t raw[MAX_TRANS_UNIT]; uint8_t len;
  ASSERT_GE(r.nextDue(WAIT, raw, len), 0);
  r.onSent(&p, WAIT + 50);
  Packet echo = repeated(p, 1);
  EXPECT_EQ(r.onHeard(&echo), FloodRetry::ECHO_HEARD);
  EXPECT_EQ(r.getStats().echoed_after, 1u);
  EXPECT_EQ(r.nextDue(10 * WAIT, raw, len), -1);         // second resend not needed
}

TEST(FloodRetry, CopyThatDidNotGoFurther_IsNotAnEcho) {
  FloodRetry r;
  Packet p = makeFlood(5, 2);       // a repeater forwarded it as hop 2
  r.track(&p, 0, 1, WAIT);
  Packet same_level = makeFlood(5, 2);
  same_level.path[1] = 0xEE;        // another node at the same distance
  EXPECT_EQ(r.onHeard(&same_level), FloodRetry::ECHO_NONE);
  Packet upstream = makeFlood(5, 1);
  EXPECT_EQ(r.onHeard(&upstream), FloodRetry::ECHO_NONE);
  EXPECT_EQ(r.getActiveCount(), 1);
  Packet further = repeated(p, 1);
  EXPECT_EQ(r.onHeard(&further), FloodRetry::ECHO_HEARD);
}

TEST(FloodRetry, OtherPacketsIgnored) {
  FloodRetry r;
  Packet p = makeFlood(6);
  r.track(&p, 0, 1, WAIT);
  Packet other = repeated(makeFlood(7), 1);
  EXPECT_EQ(r.onHeard(&other), FloodRetry::ECHO_NONE);
  Packet direct = repeated(p, 1);
  direct.header = ROUTE_TYPE_DIRECT | (PAYLOAD_TYPE_GRP_TXT << PH_TYPE_SHIFT);
  EXPECT_EQ(r.onHeard(&direct), FloodRetry::ECHO_NONE);
  EXPECT_FALSE(r.onSent(&other, 10));
  EXPECT_FALSE(r.track(&direct, 0, 1, WAIT));
}

TEST(FloodRetry, EchoWhileResendQueued_Cancels) {
  FloodRetry r;
  Packet p = makeFlood(8);
  r.track(&p, 0, 1, WAIT);
  uint8_t raw[MAX_TRANS_UNIT]; uint8_t len;
  ASSERT_GE(r.nextDue(WAIT, raw, len), 0);
  Packet echo = repeated(p, 1);
  EXPECT_EQ(r.onHeard(&echo), FloodRetry::ECHO_CANCEL_RESEND);
  EXPECT_EQ(r.onHeard(&echo), FloodRetry::ECHO_NONE);    // counted once
  uint8_t hash[MAX_HASH_SIZE];
  p.calculatePacketHash(hash);
  r.resendCancelled(hash);
  EXPECT_EQ(r.getActiveCount(), 0);
  EXPECT_EQ(r.getStats().retries, 0u);
  EXPECT_EQ(r.getStats().echoed, 1u);
  EXPECT_EQ(r.getStats().gave_up, 0u);
}

TEST(FloodRetry, EchoWhileResendTransmitting_ClosesOnSent) {
  FloodRetry r;
  Packet p = makeFlood(9);
  r.track(&p, 0, 2, WAIT);
  uint8_t raw[MAX_TRANS_UNIT]; uint8_t len;
  ASSERT_GE(r.nextDue(WAIT, raw, len), 0);
  Packet echo = repeated(p, 1);
  EXPECT_EQ(r.onHeard(&echo), FloodRetry::ECHO_CANCEL_RESEND);
  // not in the queue any more: it finishes transmitting
  EXPECT_TRUE(r.onSent(&p, WAIT + 100));
  EXPECT_EQ(r.getActiveCount(), 0);
  EXPECT_EQ(r.getStats().retries, 1u);
  EXPECT_EQ(r.nextDue(100 * WAIT, raw, len), -1);
}

TEST(FloodRetry, ResendThatNeverGoesOut_Expires) {
  FloodRetry r;
  Packet p = makeFlood(10);
  r.track(&p, 0, 1, WAIT);
  uint8_t raw[MAX_TRANS_UNIT]; uint8_t len;
  ASSERT_GE(r.nextDue(WAIT, raw, len), 0);
  EXPECT_EQ(r.nextDue(WAIT + 4 * WAIT + 29999, raw, len), -1);
  EXPECT_EQ(r.getActiveCount(), 1);
  EXPECT_EQ(r.nextDue(WAIT + 4 * WAIT + 30000, raw, len), -1);
  EXPECT_EQ(r.getActiveCount(), 0);
  EXPECT_EQ(r.getStats().gave_up, 1u);
}

TEST(FloodRetry, SlotsFull_Skipped) {
  FloodRetry r;
  for (int i = 0; i < FLOOD_RETRY_SLOTS; i++) {
    Packet p = makeFlood(20 + i * 3);
    EXPECT_TRUE(r.track(&p, 0, 1, WAIT));
  }
  Packet extra = makeFlood(99);
  EXPECT_FALSE(r.track(&extra, 0, 1, WAIT));
  EXPECT_EQ(r.getStats().skipped, 1u);
}

TEST(FloodRetry, SkipReleasesSlot) {
  FloodRetry r;
  Packet p = makeFlood(11);
  r.track(&p, 0, 1, WAIT);
  uint8_t raw[MAX_TRANS_UNIT]; uint8_t len;
  int idx = r.nextDue(WAIT, raw, len);
  ASSERT_GE(idx, 0);
  r.skip(idx);
  EXPECT_EQ(r.getActiveCount(), 0);
  EXPECT_EQ(r.getStats().skipped, 1u);
}

TEST(FloodRetry, MillisWraparound) {
  FloodRetry r;
  Packet p = makeFlood(12);
  unsigned long start = (unsigned long)-1000;   // 1 s before millis() wraps
  r.track(&p, start, 1, WAIT);
  uint8_t raw[MAX_TRANS_UNIT]; uint8_t len;
  EXPECT_EQ(r.nextDue(start + 500, raw, len), -1);
  EXPECT_EQ(r.nextDue(5, raw, len), -1);                  // wrapped, 1005 ms in
  EXPECT_GE(r.nextDue(start + WAIT, raw, len), 0);
}

TEST(FloodRetry, TransportFloodTracked) {
  FloodRetry r;
  Packet p = makeFlood(13);
  p.header = ROUTE_TYPE_TRANSPORT_FLOOD | (PAYLOAD_TYPE_GRP_TXT << PH_TYPE_SHIFT);
  p.transport_codes[0] = 0x1234; p.transport_codes[1] = 0;
  ASSERT_TRUE(r.track(&p, 0, 1, WAIT));
  uint8_t raw[MAX_TRANS_UNIT]; uint8_t len;
  ASSERT_GE(r.nextDue(WAIT, raw, len), 0);
  Packet back;
  ASSERT_TRUE(back.readFrom(raw, len));
  EXPECT_EQ(back.transport_codes[0], 0x1234);
  EXPECT_TRUE(back.isRouteFlood());
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
