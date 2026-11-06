#!/bin/bash
# Builds the libFuzzer harnesses with clang, AddressSanitizer and UBSan, into .pio/fuzz/.
# Needs the Crypto library that `pio test -e native_cli` fetches, so run that once first.
#
#   test/fuzz/build.sh
#   .pio/fuzz/fuzz_cli -dict=test/fuzz/cli.dict -max_len=600 -max_total_time=60 .pio/fuzz/corpus_cli
#   .pio/fuzz/fuzz_mesh -max_len=1200 -max_total_time=60 .pio/fuzz/corpus_mesh
#   .pio/fuzz/fuzz_meshtastic -max_len=1200 -max_total_time=60 .pio/fuzz/corpus_meshtastic
#   .pio/fuzz/fuzz_wxsensor -max_len=400 -max_total_time=60 .pio/fuzz/corpus_wxsensor
set -e
cd "$(dirname "$0")/../.."
CRYPTO=.pio/libdeps/native_cli/Crypto
[ -d $CRYPTO ] || { echo "run 'pio test -e native_cli' first, for $CRYPTO"; exit 1; }
mkdir -p .pio/fuzz
FLAGS="-std=c++17 -g -O1 -fsanitize=fuzzer,address,undefined -fno-sanitize=shift-base -fno-sanitize-recover=all
  -I test/cli_mocks -I src -I $CRYPTO -I test/mocks -I lib/ed25519"

CLI_SRC="src/helpers/CommonCLI.cpp src/helpers/CommonRadioPrefs.cpp src/helpers/RegionMap.cpp
  src/helpers/ClientACL.cpp src/helpers/TransportKeyStore.cpp src/helpers/TxtDataHelpers.cpp
  src/helpers/AdvertDataHelpers.cpp src/helpers/ConfigSerializer.cpp src/helpers/DynamicConfigSerializer.cpp
  src/Identity.cpp src/Utils.cpp src/Packet.cpp
  $CRYPTO/AES128.cpp $CRYPTO/AESCommon.cpp $CRYPTO/BlockCipher.cpp $CRYPTO/Crypto.cpp $CRYPTO/Hash.cpp
  $CRYPTO/SHA256.cpp $CRYPTO/SHA512.cpp $CRYPTO/Ed25519.cpp $CRYPTO/Curve25519.cpp $CRYPTO/BigNumberUtil.cpp"

# ed25519 is C: build it as C, then link
mkdir -p .pio/fuzz/obj
for c in lib/ed25519/*.c; do
  clang -g -O1 -fsanitize=fuzzer-no-link,address,undefined -fno-sanitize=shift-base -I lib/ed25519 \
    -c $c -o .pio/fuzz/obj/$(basename $c .c).o
done

clang++ $FLAGS test/fuzz/fuzz_cli.cpp $CLI_SRC .pio/fuzz/obj/*.o -o .pio/fuzz/fuzz_cli
echo "built .pio/fuzz/fuzz_cli"

# the radio receive path, with pass-through crypto (test/fuzz/mocks) and no ed25519
BASE64=.pio/libdeps/native_cli/base64/src
MESH_SRC="src/Dispatcher.cpp src/Mesh.cpp src/Packet.cpp src/Utils.cpp src/CryptoV2.cpp src/AesSiv.cpp
  src/helpers/BaseChatMesh.cpp src/helpers/AdvertDataHelpers.cpp src/helpers/TxtDataHelpers.cpp
  src/helpers/StaticPoolPacketManager.cpp"
clang++ -std=c++17 -g -O1 -fsanitize=fuzzer,address,undefined -fno-sanitize=shift-base -fno-sanitize-recover=all \
  -DMAX_GROUP_CHANNELS=4 -DMAX_CONTACTS=8 \
  -I test/fuzz/mocks -I test/cli_mocks -I src -I $BASE64 -I test/mocks \
  test/fuzz/fuzz_mesh.cpp $MESH_SRC -o .pio/fuzz/fuzz_mesh
echo "built .pio/fuzz/fuzz_mesh"

# Meshtastic decoding, with the real AES
clang++ -std=c++17 -g -O1 -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all \
  -I src -I $CRYPTO \
  test/fuzz/fuzz_meshtastic.cpp src/helpers/meshtastic/MeshtasticRx.cpp \
  $CRYPTO/AES128.cpp $CRYPTO/AES256.cpp $CRYPTO/AESCommon.cpp $CRYPTO/BlockCipher.cpp $CRYPTO/Crypto.cpp \
  -o .pio/fuzz/fuzz_meshtastic
echo "built .pio/fuzz/fuzz_meshtastic"

# weather sensor decoding and listen scheduling
clang++ -std=c++17 -g -O1 -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all \
  -I src test/fuzz/fuzz_wxsensor.cpp src/helpers/weather/FineOffset.cpp src/helpers/weather/LaCrosse.cpp src/helpers/weather/SensorTracker.cpp \
  -o .pio/fuzz/fuzz_wxsensor
echo "built .pio/fuzz/fuzz_wxsensor"

# Aircraft messages: UAT (978 MHz) and ADS-B (1090 MHz)
clang++ -std=c++17 -g -O1 -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all \
  -I src test/fuzz/fuzz_uat.cpp src/helpers/aircraft/Uat.cpp src/helpers/aircraft/AdsB.cpp src/helpers/aircraft/RadarSweep.cpp -o .pio/fuzz/fuzz_uat
echo "built .pio/fuzz/fuzz_uat"
