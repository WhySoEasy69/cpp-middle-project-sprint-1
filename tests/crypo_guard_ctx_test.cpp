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

    ASSERT_EQ(iss.str(), decryptedOss.str());
}

TEST_F(CryptoGuardTest, DecryptInvalidInputArg) {
    iss.setstate(std::ios::failbit);

    ASSERT_THROW(guard.Decrypt(iss, oss, pass), std::exception);
}

TEST_F(CryptoGuardTest, DecryptInvalidOutputArg) {
    oss.setstate(std::ios::failbit);

    ASSERT_THROW(guard.Decrypt(iss, oss, pass), std::exception);
}
