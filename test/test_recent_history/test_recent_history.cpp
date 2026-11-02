#include <gtest/gtest.h>
#include "helpers/RecentHistory.h"

TEST(RecentHistory, StartsEmpty) {
  RecentHistory<int, 3> h;
  EXPECT_EQ(0, h.count());
  EXPECT_EQ(0u, h.total());
}

TEST(RecentHistory, NewestFirstBeforeFull) {
  RecentHistory<int, 3> h;
  h.add(1);
  h.add(2);
  EXPECT_EQ(2, h.count());
  EXPECT_EQ(2, h.get(0));
  EXPECT_EQ(1, h.get(1));
}

TEST(RecentHistory, OverwritesOldestWhenFull) {
  RecentHistory<int, 3> h;
  for (int i = 1; i <= 5; i++) h.add(i);
  EXPECT_EQ(3, h.count());
  EXPECT_EQ(5u, h.total());
  EXPECT_EQ(5, h.get(0));
  EXPECT_EQ(4, h.get(1));
  EXPECT_EQ(3, h.get(2));
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
