#include <gtest/gtest.h>
#include "../../examples/companion_radio/SyncBatch.h"

// A model of the offline queue: message ids, oldest first
struct Queue {
  int items[64];
  int len = 0;
  int next_id = 1;
  void push() { items[len++] = next_id++; }
  void removeFront(int n) {
    for (int i = n; i < len; i++) items[i - n] = items[i];
    len -= n;
  }
  void removeAt(int pos) {
    for (int i = pos; i < len - 1; i++) items[i] = items[i + 1];
    len--;
  }
};

// One batch request: confirm `ack`, then send up to `max`. Returns the ids sent.
static int request(SyncBatch& b, Queue& q, int max, int ack, int out[]) {
  q.removeFront(b.confirm(ack));
  b.start(max);
  int n = 0, idx;
  while ((idx = b.next(q.len)) >= 0) {
    out[n++] = q.items[idx];
    b.markSent();
  }
  b.sending = false;
  return n;
}

TEST(SyncBatch, SendsWithoutRemovingUntilConfirmed) {
  SyncBatch b;
  Queue q;
  for (int i = 0; i < 5; i++) q.push();
  int got[64];
  EXPECT_EQ(request(b, q, 3, 0, got), 3);
  EXPECT_EQ(got[0], 1);
  EXPECT_EQ(got[2], 3);
  EXPECT_EQ(q.len, 5);   // still there
  EXPECT_EQ(request(b, q, 3, 3, got), 2);
  EXPECT_EQ(got[0], 4);
  EXPECT_EQ(q.len, 2);
  EXPECT_EQ(request(b, q, 3, 2, got), 0);
  EXPECT_EQ(q.len, 0);
}

TEST(SyncBatch, UnconfirmedComeAgain) {
  SyncBatch b;
  Queue q;
  for (int i = 0; i < 4; i++) q.push();
  int got[64];
  request(b, q, 4, 0, got);
  // the link dropped: the next connection starts with ack 0
  b.cancel();
  EXPECT_EQ(request(b, q, 4, 0, got), 4);
  EXPECT_EQ(got[0], 1);
}

TEST(SyncBatch, AckIsCapped) {
  SyncBatch b;
  Queue q;
  for (int i = 0; i < 5; i++) q.push();
  int got[64];
  request(b, q, 2, 0, got);
  EXPECT_EQ(b.confirm(200), 2);
  EXPECT_EQ(b.confirm(2), 0);   // nothing sent since
}

TEST(SyncBatch, DroppedWhileUnconfirmed) {
  SyncBatch b;
  Queue q;
  for (int i = 0; i < 4; i++) q.push();
  int got[64];
  request(b, q, 3, 0, got);   // 1, 2, 3 sent
  // the queue filled up and message 2 was dropped for a new one
  q.removeAt(1);
  b.onRemoved(1);
  q.push();
  EXPECT_EQ(b.sent, 2);
  q.removeFront(b.confirm(3));   // the app confirms the 3 it got
  // 1 and 3 gone, 4 and the new 5 left: nothing the app didn't get was removed
  EXPECT_EQ(q.len, 2);
  EXPECT_EQ(q.items[0], 4);
}

TEST(SyncBatch, DroppedAfterTheSentOnes) {
  SyncBatch b;
  Queue q;
  for (int i = 0; i < 4; i++) q.push();
  int got[64];
  request(b, q, 2, 0, got);
  b.onRemoved(3);
  EXPECT_EQ(b.sent, 2);
}

TEST(SyncBatch, CancelKeepsMessages) {
  SyncBatch b;
  Queue q;
  for (int i = 0; i < 3; i++) q.push();
  int got[64];
  request(b, q, 3, 0, got);
  b.cancel();   // CMD_SYNC_NEXT_MESSAGE
  EXPECT_EQ(b.confirm(3), 0);
  EXPECT_EQ(q.len, 3);
}

TEST(SyncBatch, ConfirmOnly) {
  SyncBatch b;
  Queue q;
  for (int i = 0; i < 2; i++) q.push();
  int got[64];
  request(b, q, 2, 0, got);
  EXPECT_EQ(request(b, q, 0, 2, got), 0);
  EXPECT_EQ(q.len, 0);
}

TEST(SyncBatch, LimitIsCappedAt255) {
  SyncBatch b;
  b.start(1000);
  EXPECT_EQ(b.limit, 255);
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
