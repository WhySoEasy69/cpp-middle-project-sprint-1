#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <algorithm>
#include <array>
#include <iostream>
#include <openssl/evp.h>
#include <print>
#include <stdexcept>
#include <string>

void ProcessCryptoCommand(CryptoGuard::ProgramOptions::COMMAND_TYPE type) {
    using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
    CryptoGuard::CryptoGuardCtx guard;
    switch (type) {
    case COMMAND_TYPE::ENCRYPT:
        // guard.Encrypt();
        std::print("File encoded successfully\n");
        break;

    case COMMAND_TYPE::DECRYPT:
        // guard.Decrypt();
        std::print("File decoded successfully\n");
        break;

    case COMMAND_TYPE::CHECKSUM:
        // TODO: support too much args error for checksum
        // auto res = guard.CalculateChecksum();
        // std::print("Checksum: {}\n", res);
        break;

    default:
        std::print("Unsupported command\n");
        throw std::runtime_error{"Unsupported command"};
    }
}

void Process(const CryptoGuard::ProgramOptions &options) {
    if (options.IsHelpRequested()) {
        options.PrintHelpInfo();
    } else {
        // TODO: get options and pass to ProcessCryptoCommand
        ProcessCryptoCommand(options.GetCommand());
    }
}

int main(int argc, char *argv[]) {
    try {
        CryptoGuard::ProgramOptions options;
        options.Parse(argc, argv);

        Process(options);

    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    } catch (...) {
        std::print(std::cerr, "Unknown error occurred");
        return 1;
    }

    return 0;
}