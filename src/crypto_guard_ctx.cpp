#include "crypto_guard_ctx.h"
#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <iomanip>
#include <iterator>
#include <memory>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <span>
#include <stdexcept>
#include <vector>

namespace CryptoGuard {

struct AesCipherParams {
    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
};

AesCipherParams CreateCipherParamsFromPassword(std::string_view password) {
    AesCipherParams params;
    constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

    int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                params.key.data(), params.iv.data());

    if (result == 0) {
        throw std::runtime_error{"Failed to create a key from password"};
    }

    return params;
}

enum class CRYPTO_OPERATION_TYPE : int {
    DECRYPT = 0,
    ENCRYPT = 1,
};

std::string GetCryptoOperationTypeStr(CRYPTO_OPERATION_TYPE type) {
    switch (type) {
    case CRYPTO_OPERATION_TYPE::DECRYPT:
        return "Decrypt";
    case CRYPTO_OPERATION_TYPE::ENCRYPT:
        return "Encrypt";
    default:
        assert(false);
        return "Unknown";
    }
}

using EvpCipherCtxPtr =
    std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX *ctx) { EVP_CIPHER_CTX_free(ctx); })>;

using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, decltype([](EVP_MD_CTX *ctx) { EVP_MD_CTX_free(ctx); })>;

class CryptoGuardCtx::Impl {
public:
    Impl() : buffSizeForCrypto_(64 * 1024), evpCtxPtr_(EVP_CIPHER_CTX_new()) {
        if (!evpCtxPtr_) {
            throw std::runtime_error("failed to create EVP_CIPHER_CTX");
        }

        OpenSSL_add_all_algorithms();
    }

    ~Impl() { EVP_cleanup(); }

    void Encrypt(std::istream &inStream, std::ostream &outStream, std::string_view password) {
        processCryptoOperation(inStream, outStream, password, CRYPTO_OPERATION_TYPE::ENCRYPT);
    }

    void Decrypt(std::istream &inStream, std::ostream &outStream, std::string_view password) {
        processCryptoOperation(inStream, outStream, password, CRYPTO_OPERATION_TYPE::DECRYPT);
    }

    std::string CalculateChecksum(std::istream &inStream) const {
        if (!inStream.good()) {
            throw std::invalid_argument("invalid input stream argument");
        }

        auto md = EVP_sha256();
        if (!md) {
            auto opensslErr = getOpensslErrorDesc();
            throw std::runtime_error("EVP_sha256 failed: " + opensslErr);
        }

        EvpMdCtxPtr mdCtxPtr(EVP_MD_CTX_new());
        if (!mdCtxPtr) {
            throw std::runtime_error("failed to create evp md ctx, " + getOpensslErrorDesc());
        }

        if (!EVP_DigestInit_ex2(mdCtxPtr.get(), md, nullptr)) {
            throw std::runtime_error("digest initialization failed, " + getOpensslErrorDesc());
        }

        std::vector<unsigned char> buff(buffSizeForCrypto_);
        while (inStream.good()) {
            inStream.read(reinterpret_cast<char *>(buff.data()), buff.size());
            const auto readCount = inStream.gcount();

            if (!EVP_DigestUpdate(mdCtxPtr.get(), buff.data(), static_cast<size_t>(readCount))) {
                throw std::runtime_error("digest update failed, " + getOpensslErrorDesc());
            }
        }

        std::array<unsigned char, EVP_MAX_MD_SIZE> mdValue;
        unsigned int mdLen = 0;

        if (!EVP_DigestFinal_ex(mdCtxPtr.get(), reinterpret_cast<unsigned char *>(mdValue.data()), &mdLen)) {
            throw std::runtime_error("digest finalization failed, " + getOpensslErrorDesc());
        }

        return convertToHex(std::span(mdValue.data(), mdLen));
    }

private:
    void processCryptoOperation(std::istream &inStream, std::ostream &outStream, std::string_view password,
                                CRYPTO_OPERATION_TYPE type) {
        auto opStr = GetCryptoOperationTypeStr(type);

        if (!inStream.good()) {
            throw std::invalid_argument(opStr + " failed: Invalid input stream argument");
        } else if (!outStream) {
            throw std::invalid_argument(opStr + " failed: Invalid outstream argument");
        }

        const auto params = CreateCipherParamsFromPassword(password);

        const auto enc = static_cast<int>(type);

        auto opcode =
            EVP_CipherInit_ex(evpCtxPtr_.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), enc);
        checkOpensslOpcode(opStr + " EVP_CipherInit_ex failed: ", opcode);

        std::vector<unsigned char> inBuf(buffSizeForCrypto_);
        std::vector<unsigned char> outBuf(buffSizeForCrypto_ + EVP_MAX_BLOCK_LENGTH);

        while (inStream.good()) {
            inStream.read(reinterpret_cast<char *>(inBuf.data()), inBuf.size());
            const auto readCount = inStream.gcount();

            int outLen = 0;

            opcode =
                EVP_CipherUpdate(evpCtxPtr_.get(), outBuf.data(), &outLen, inBuf.data(), static_cast<int>(readCount));
            checkOpensslOpcode(opStr + " EVP_CipherUpdate failed: ", opcode);

            std::copy(outBuf.begin(), std::next(outBuf.begin(), outLen), std::ostreambuf_iterator<char>(outStream));
        }

        std::vector<unsigned char> finalOutBuf(EVP_MAX_BLOCK_LENGTH);
        int finalLen = 0;

        opcode = EVP_CipherFinal_ex(evpCtxPtr_.get(), finalOutBuf.data(), &finalLen);
        checkOpensslOpcode(opStr + " EVP_CipherFinal_ex failed: ", opcode);

        std::copy(finalOutBuf.begin(), std::next(finalOutBuf.begin(), finalLen),
                  std::ostreambuf_iterator<char>(outStream));
    }

    void checkOpensslOpcode(const std::string &errContextInfo, int opcode) const {
        if (opcode != 1) {
            throw std::runtime_error(errContextInfo + getOpensslErrorDesc());
        }
    }

    std::string getOpensslErrorDesc() const {
        auto errCode = ERR_get_error();
        std::string errBuff(256, '\0');
        ERR_error_string_n(errCode, errBuff.data(), errBuff.size());
        return errBuff;
    }

    std::string convertToHex(std::span<unsigned char> data) const {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (unsigned int i = 0; i < data.size(); ++i) {
            oss << std::setw(2) << static_cast<unsigned int>(data[i]);
        }
        return oss.str();
    }

private:
    const size_t buffSizeForCrypto_;
    EvpCipherCtxPtr evpCtxPtr_;
};

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<Impl>()) {}

CryptoGuardCtx::~CryptoGuardCtx() {}

void CryptoGuardCtx::Encrypt(std::istream &inStream, std::ostream &outStream, std::string_view password) {
    pImpl_->Encrypt(inStream, outStream, password);
}

void CryptoGuardCtx::Decrypt(std::istream &inStream, std::ostream &outStream, std::string_view password) {
    pImpl_->Decrypt(inStream, outStream, password);
}

std::string CryptoGuardCtx::CalculateChecksum(std::istream &inStream) const {
    return pImpl_->CalculateChecksum(inStream);
}

}  // namespace CryptoGuard
