#include <gtest/gtest.h>
#include "helpers/ConsoleName.h"

TEST(ConsoleName, Matches) {
  EXPECT_TRUE(ConsoleName::looksLikeConsole("Radio console"));
  EXPECT_TRUE(ConsoleName::looksLikeConsole("RADIO CONSOLE"));
  EXPECT_TRUE(ConsoleName::looksLikeConsole("radio_console"));
  EXPECT_TRUE(ConsoleName::looksLikeConsole("Radio  console "));
  EXPECT_TRUE(ConsoleName::looksLikeConsole("\xF0\x9F\x93\xBB Radio console"));        // 📻 in front
  EXPECT_TRUE(ConsoleName::looksLikeConsole("Radio\xE2\x80\x8B console"));             // zero-width space
  EXPECT_TRUE(ConsoleName::looksLikeConsole("Radi\xD0\xBE console"));                  // Cyrillic о
  EXPECT_TRUE(ConsoleName::looksLikeConsole("Rad1o c0nsole"));
}

TEST(ConsoleName, OtherNamesPass) {
  EXPECT_FALSE(ConsoleName::looksLikeConsole("Radio"));
  EXPECT_FALSE(ConsoleName::looksLikeConsole("Console Repeater"));
  EXPECT_FALSE(ConsoleName::looksLikeConsole("Radio console 2"));
  EXPECT_FALSE(ConsoleName::looksLikeConsole("Radio consoles"));
  EXPECT_FALSE(ConsoleName::looksLikeConsole("DEN-BLDR-BRDWY-RE-8A65"));
  EXPECT_FALSE(ConsoleName::looksLikeConsole(""));
  EXPECT_FALSE(ConsoleName::looksLikeConsole("\xD0\x9F\xD1\x80\xD0\xB8\xD0\xB2\xD0\xB5\xD1\x82 \xD0\xBC\xD0\xB8\xD1\x80"));  // Привет мир
}

TEST(ConsoleName, MarkFake) {
  char out[32];
  ConsoleName::markFake(out, sizeof(out), "Radio console");
  EXPECT_STREQ(out, "(fake) Radio console");
  ConsoleName::markFake(out, sizeof(out), "\xF0\x9F\x93\xBB Radio console xxxxxxxxxxxx");
  EXPECT_LT(strlen(out), sizeof(out));
  EXPECT_EQ(strncmp(out, "(fake) \xF0\x9F\x93\xBB", 11), 0);
  ConsoleName::markFake(out, sizeof(out), "abcdefghijklmnopqrstuvw\xD0\xBE");   // the 2-byte char doesn't fit whole
  EXPECT_STREQ(out, "(fake) abcdefghijklmnopqrstuvw");
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
