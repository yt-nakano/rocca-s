extern "C" {
#include "rocca-s.h"
}

#include "gtest/gtest.h"
#include "absl/strings/escaping.h"

using namespace std;

namespace security {

namespace roccas {


struct TestVector {
  std::string key;
  std::string iv;
  std::string ad;
  std::string plaintext;
  std::string ciphertext;
  std::string tag;
};

std::vector<TestVector>* test_vectors = new std::vector<TestVector>({{
      // 1
      {
        "0000000000000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "9ac3326495a8d414fe407f47b54410502481cf79cab8c0a669323e07711e46170de5b2fbba0fae8de7c1fccaeefc362624fcfdc15f8bb3e64457e8b7e37557bb",
        "8df934d1483710c9410f6a089c4ced9791901b7e2e661206202db2cc7a24a386"
      },
      // 2
      {
        "0101010101010101010101010101010101010101010101010101010101010101",
        "01010101010101010101010101010101",
        "0101010101010101010101010101010101010101010101010101010101010101",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "559ecb253bcfe26b483bf00e9c748345978ff921036a6c1fdcb712172836504fbc64d430a73fc67acd3c3b9c1976d80790f48357e7fe0c0682624569d3a658fb",
        "c1fdf39762eca77da8b0f1dae5fff75a92fb0adfa7940a28c8cadbbbe8e4ca8d"
      },
      // 3
      {
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "0123456789abcdef0123456789abcdef",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "b5fc4e2a72b86d1a133c0f0202bdf790af14a24b2cdb676e427865e12fcc9d3021d18418fc75dc1912dd2cd79a3beeb2a98b235de2299b9dda93fd2b5ac8f436",
        "a078e1351ef2420c8e3a93fd31f5b1135b15315a5f205534148efbcd63f79f00"
      },
      // 4
      {
        "1111111111111111111111111111111122222222222222222222222222222222",
        "44444444444444444444444444444444",
        "",
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7",
        "e8c7adcc58302893b253c544f5d8e62d8fbd81160c2f4a95123962088d29f106422d3f26882fd7b1",
        "f650eba86fb19dc14a3bbe8bbfad9ec5b5dd77a4c3f83d2c19ac0393dd47928f"
      },
      // 5
      {
        "1111111111111111111111111111111122222222222222222222222222222222",
        "44444444444444444444444444444444",
        "",
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
        "e8c7adcc58302893b253c544f5d8e62d8fbd81160c2f4a95123962088d29f106422d3f26882fd7b1fdee5680476e7e6e",
        "49bb0ec78cab2c5f40a535925fa2d82752aba9606426537fc774f06fc0f6fc12"
      },
      // 6
      {
        "1111111111111111111111111111111122222222222222222222222222222222",
        "44444444444444444444444444444444",
        "",
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8",
        "e8c7adcc58302893b253c544f5d8e62d8fbd81160c2f4a95123962088d29f106422d3f26882fd7b1fdee5680476e7e6e1fc473cdb2dded85c6",
        "c674604803963a4b51685fda1f2aa043934736db2fbab6d188a09f5e0d1c0bf3"
      },
      // 7
      {
        "1111111111111111111111111111111122222222222222222222222222222222",
        "44444444444444444444444444444444",
        "",
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
        "e8c7adcc58302893b253c544f5d8e62d8fbd81160c2f4a95123962088d29f106422d3f26882fd7b1fdee5680476e7e6e1fc473cdb2dded85c692344f3ab85af0",
        "850599a6624a3e936a77768c7717b926cc519081730df447127654d6980bcb02"
      }
    }});


class RoccasTest : public testing::Test {
 public:

  static void hexstringtochar(const std::string& str_hex, uint8_t* bin) {

    std::string tmp = absl::HexStringToBytes(str_hex);

    vector<uint8_t> tmp_vec(tmp.begin(), tmp.end());

    memcpy(bin, &tmp_vec[0], str_hex.size() / 2);
  }


  static bool EncryptHex(const std::string& key_hex,
                         const std::string& iv_hex,
                         const std::string& ad_hex,
                         const std::string& plaintext_hex,
                         std::string* ciphertext_hex,
                         std::string* tag_hex) {

    rocca_context ctx;

    uint8_t key[1024];
    uint8_t iv[1024];
    uint8_t ad[1024];
    uint8_t plaintext[1024];

    hexstringtochar(key_hex, key);
    hexstringtochar(iv_hex, iv);
    hexstringtochar(ad_hex, ad);
    hexstringtochar(plaintext_hex, plaintext);

    uint8_t ciphertext[1024] = {0};
    uint8_t tag[ROCCA_TAG_SIZE] = {0};

    rocca_init(&ctx, key, iv);
    rocca_add_ad(&ctx, ad, ad_hex.size() / 2);
    rocca_encrypt(&ctx, ciphertext, plaintext, plaintext_hex.size() / 2);
    rocca_tag(&ctx, tag);

    *ciphertext_hex = absl::BytesToHexString(
      absl::string_view(reinterpret_cast<const char *>(ciphertext), plaintext_hex.size() / 2));
    *tag_hex = absl::BytesToHexString(
      absl::string_view(reinterpret_cast<const char *>(tag), ROCCA_TAG_SIZE));

    return true;
  }

  static bool DecryptHex(const std::string& key_hex,
                         const std::string& iv_hex,
                         const std::string& ad_hex,
                         const std::string& ciphertext_hex,
                         std::string* plaintext_hex,
                         std::string* tag_hex) {

    rocca_context ctx;

    uint8_t key[1024];
    uint8_t iv[1024];
    uint8_t ad[1024];
    uint8_t ciphertext[1024];

    hexstringtochar(key_hex, key);
    hexstringtochar(iv_hex, iv);
    hexstringtochar(ad_hex, ad);
    hexstringtochar(ciphertext_hex, ciphertext);

    uint8_t plaintext[1024] = {0};
    uint8_t tag[ROCCA_TAG_SIZE] = {0};

    rocca_init(&ctx, key, iv);
    rocca_add_ad(&ctx, ad, ad_hex.size() / 2);
    rocca_decrypt(&ctx, plaintext, ciphertext, ciphertext_hex.size() / 2);
    rocca_tag(&ctx, tag);

    *plaintext_hex = absl::BytesToHexString(
      absl::string_view(reinterpret_cast<const char *>(plaintext), ciphertext_hex.size() / 2));
    *tag_hex = absl::BytesToHexString(
      absl::string_view(reinterpret_cast<const char *>(tag), ROCCA_TAG_SIZE));

    return true;
  }
};


TEST_F(RoccasTest, TestVectorsEncrypt) {
  for (const TestVector& v : *test_vectors) {
    std::string ciphertext;
    std::string tag;
    bool ok =
      EncryptHex(v.key, v.iv, v.ad, v.plaintext, &ciphertext, &tag);
    ASSERT_TRUE(ok);
    EXPECT_EQ(v.ciphertext, ciphertext);
    EXPECT_EQ(v.tag, tag);
  }
}

TEST_F(RoccasTest, TestVectorsDecrypt) {
  for (const TestVector& v : *test_vectors) {
    std::string plaintext;
    std::string tag;
    bool ok =
      DecryptHex(v.key, v.iv, v.ad, v.ciphertext, &plaintext, &tag);
    ASSERT_TRUE(ok);
    EXPECT_EQ(v.plaintext, plaintext);
    EXPECT_EQ(v.tag, tag);
  }
}


}  // namespace roccas

}  // namespace security
