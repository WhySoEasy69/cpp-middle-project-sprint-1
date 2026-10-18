#include "crypto_guard_ctx.h"
#include <gtest/gtest.h>
#include <sstream>

class CryptoGuardTest : public ::testing::Test {
protected:
    std::istringstream iss{"hello world"};
    std::ostringstream oss;
    std::string pass = "12345";
    CryptoGuard::CryptoGuardCtx guard;
};

TEST_F(CryptoGuardTest, EncryptSuccess) {
    guard.Encrypt(iss, oss, pass);
    std::string res = oss.str();

    ASSERT_TRUE(!res.empty());
}

TEST_F(CryptoGuardTest, EncryptInvalidInputArg) {
    iss.setstate(std::ios::failbit);

    ASSERT_THROW(guard.Encrypt(iss, oss, pass), std::exception);
}

TEST_F(CryptoGuardTest, EncryptInvalidOutputArg) {
    oss.setstate(std::ios::failbit);

    ASSERT_THROW(guard.Encrypt(iss, oss, pass), std::exception);
}

TEST_F(CryptoGuardTest, DecryptSuccess) {
    guard.Encrypt(iss, oss, pass);

    std::istringstream encryptedIss(oss.str());
    std::ostringstream decryptedOss;

    guard.Decrypt(encryptedIss, decryptedOss, pass);

    auto inputMsg = iss.str();
    auto decryptedMsg = decryptedOss.str();

    ASSERT_TRUE(!inputMsg.empty() && !decryptedMsg.empty());

    ASSERT_EQ(inputMsg, decryptedMsg);
}

TEST_F(CryptoGuardTest, DecryptInvalidInputArg) {
    iss.setstate(std::ios::failbit);

    ASSERT_THROW(guard.Decrypt(iss, oss, pass), std::exception);
}

TEST_F(CryptoGuardTest, DecryptInvalidOutputArg) {
    oss.setstate(std::ios::failbit);

    ASSERT_THROW(guard.Decrypt(iss, oss, pass), std::exception);
}

TEST(CryptoGuardChecksumTest, EqualValuesEqualChecksum) {
    CryptoGuard::CryptoGuardCtx guard;
    std::string msg = "hello world";
    std::istringstream iss1(msg);
    std::istringstream iss2(msg);

    auto res1 = guard.CalculateChecksum(iss1);
    auto res2 = guard.CalculateChecksum(iss2);

    ASSERT_TRUE(!res1.empty());
    ASSERT_TRUE(!res2.empty());

    EXPECT_EQ(res1, res2);
}

TEST(CryptoGuardChecksumTest, DifferentValuesDifferentChecksum) {
    CryptoGuard::CryptoGuardCtx guard;

    std::istringstream iss1("hello world");
    std::istringstream iss2("hi world");

    auto res1 = guard.CalculateChecksum(iss1);
    auto res2 = guard.CalculateChecksum(iss2);

    ASSERT_TRUE(!res1.empty());
    ASSERT_TRUE(!res2.empty());

    EXPECT_NE(res1, res2);
}

TEST(CryptoGuardChecksumTest, CalculateChecksumInvalidInputArg) {
    CryptoGuard::CryptoGuardCtx guard;
    std::istringstream iss("hello world");
    iss.setstate(std::ios::failbit);

    ASSERT_THROW(guard.CalculateChecksum(iss), std::exception);
}

TEST_F(CryptoGuardTest, ChecksumNotChangedAfterDecryption) {
    auto res1 = guard.CalculateChecksum(iss);
    iss.clear();
    iss.seekg(0);

    guard.Encrypt(iss, oss, pass);

    std::istringstream encryptedIss(oss.str());
    std::ostringstream decryptedOss;

    guard.Decrypt(encryptedIss, decryptedOss, pass);

    std::istringstream iss2(decryptedOss.str());
    auto res2 = guard.CalculateChecksum(iss2);

    ASSERT_TRUE(!res1.empty());
    ASSERT_TRUE(!res2.empty());

    ASSERT_EQ(res1, res2);
}