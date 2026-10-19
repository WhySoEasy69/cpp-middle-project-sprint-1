#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <fstream>
#include <iostream>
#include <openssl/evp.h>
#include <print>
#include <stdexcept>
#include <string>

void processEncrypt(const CryptoGuard::ProgramOptions &options) {
    auto inputFilePath = options.GetInputFile();
    auto outputFilePath = options.GetOutputFile();
    auto password = options.GetPassword();

    std::ifstream inputFile(inputFilePath);
    std::ofstream outputFile(outputFilePath);

    if (!inputFile.is_open()) {
        throw std::runtime_error("failed to open input file");
    } else if (!outputFile.is_open()) {
        throw std::runtime_error("failed to open output file");
    }

    CryptoGuard::CryptoGuardCtx guard;

    guard.Encrypt(inputFile, outputFile, password);
}

void processDecrypt(const CryptoGuard::ProgramOptions &options) {
    auto inputFilePath = options.GetInputFile();
    auto outputFilePath = options.GetOutputFile();
    auto password = options.GetPassword();

    std::ifstream inputFile(inputFilePath);
    std::ofstream outputFile(outputFilePath);

    if (!inputFile.is_open()) {
        throw std::runtime_error("failed to open input file");
    } else if (!outputFile.is_open()) {
        throw std::runtime_error("failed to open output file");
    }

    CryptoGuard::CryptoGuardCtx guard;

    guard.Decrypt(inputFile, outputFile, password);
}

std::string processChecksum(const CryptoGuard::ProgramOptions &options) {
    auto inputFilePath = options.GetInputFile();

    std::ifstream inputFile(inputFilePath);

    if (!inputFile.is_open()) {
        throw std::runtime_error("failed to open input file");
    }

    CryptoGuard::CryptoGuardCtx guard;

    return guard.CalculateChecksum(inputFile);
}

void ProcessCryptoCommand(CryptoGuard::ProgramOptions::COMMAND_TYPE type, const CryptoGuard::ProgramOptions &options) {
    using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
    CryptoGuard::CryptoGuardCtx guard;
    switch (type) {
    case COMMAND_TYPE::ENCRYPT:
        processEncrypt(options);
        std::print("File encoded successfully\n");
        break;

    case COMMAND_TYPE::DECRYPT:
        processDecrypt(options);
        std::print("File decoded successfully\n");
        break;

    case COMMAND_TYPE::CHECKSUM: {
        auto res = processChecksum(options);
        std::print("Checksum: {}\n", res);
        break;
    }
    default:
        std::print("Unsupported command\n");
        throw std::runtime_error{"Unsupported command"};
    }
}

void Process(const CryptoGuard::ProgramOptions &options) {
    if (options.IsHelpRequested()) {
        options.PrintHelpInfo();
    } else {
        ProcessCryptoCommand(options.GetCommand(), options);
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