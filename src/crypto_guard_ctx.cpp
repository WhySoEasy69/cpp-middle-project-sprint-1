#include "crypto_guard_ctx.h"
#include <algorithm>
#include <array>
#include <cstddef>
#include <iterator>
#include <memory>
#include <openssl/err.h>
#include <openssl/evp.h>
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

using EvpCipherCtxPtr =
    std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX *ctx) { EVP_CIPHER_CTX_free(ctx); })>;

class CryptoGuardCtx::Impl {
public:
    Impl() : evpCtxPtr_(EVP_CIPHER_CTX_new()) {
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

    std::string CalculateChecksum(std::istream &inStream) {
        if (inStream) {
            throw std::invalid_argument("invalid input stream argument");
        }

        return "NOT_IMPLEMENTED";
    }

private:
    void processCryptoOperation(std::istream &inStream, std::ostream &outStream, std::string_view password,
                                CRYPTO_OPERATION_TYPE type) {
        if (!inStream) {
            throw std::invalid_argument("invalid input stream argument");
        } else if (!outStream) {
            throw std::invalid_argument("invalid outstream argument");
        }

        const auto params = CreateCipherParamsFromPassword(password);

        const auto enc = static_cast<int>(type);
        auto opcode =
            EVP_CipherInit_ex(evpCtxPtr_.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), enc);
        checkOpensslOpcode("EVP_CipherInit_ex", opcode);

        // TODO: read and process data by chunks
        // TODO: replace implicit char to unsigned chars conversions ?
        std::vector<unsigned char> inBuf;
        std::copy(std::istreambuf_iterator<char>(inStream), std::istreambuf_iterator<char>(),
                  std::back_inserter(inBuf));

        std::vector<unsigned char> outBuf(inBuf.size() + EVP_MAX_BLOCK_LENGTH);
        int outLen;

        opcode =
            EVP_CipherUpdate(evpCtxPtr_.get(), outBuf.data(), &outLen, inBuf.data(), static_cast<int>(inBuf.size()));
        checkOpensslOpcode("EVP_CipherUpdate", opcode);

        int finalLen;
        opcode = EVP_CipherFinal_ex(evpCtxPtr_.get(), outBuf.data() + outLen, &finalLen);
        checkOpensslOpcode("EVP_CipherFinal_ex", opcode);

        const auto len = outLen + finalLen;
        std::copy(outBuf.begin(), std::next(outBuf.begin(), len), std::ostreambuf_iterator<char>(outStream));
    }

    void checkOpensslOpcode(std::string opDesc, int opcode) {
        if (opcode != 1) {
            auto errCode = ERR_get_error();
            std::string errBuf(256, '\0');
            ERR_error_string_n(errCode, errBuf.data(), errBuf.size());
            throw std::runtime_error(opDesc + ": " + errBuf);
        }
    }

private:
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

std::string CryptoGuardCtx::CalculateChecksum(std::istream &inStream) { return pImpl_->CalculateChecksum(inStream); }

}  // namespace CryptoGuard
