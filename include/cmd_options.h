#pragma once

#include <boost/program_options.hpp>
#include <iostream>
#include <string>
#include <unordered_map>

namespace CryptoGuard {

class ProgramOptions {
public:
    ProgramOptions();

    enum class COMMAND_TYPE {
        ENCRYPT,
        DECRYPT,
        CHECKSUM,
    };

    void Parse(int argc, const char* const* argv);

    bool IsHelpRequested() const { return isHelpRequested_; }
    void PrintHelpInfo() const { desc_.print(std::cout); }

    COMMAND_TYPE GetCommand() const { return command_; }
    std::string GetInputFile() const { return inputFile_; }
    std::string GetOutputFile() const { return outputFile_; }
    std::string GetPassword() const { return password_; }

private:
    void SetParsedCommand(const std::string &command);
    void Validate(const boost::program_options::variables_map &vm);

private:
    COMMAND_TYPE command_;
    const std::unordered_map<std::string_view, COMMAND_TYPE> commandMapping_ = {
        {"encrypt", ProgramOptions::COMMAND_TYPE::ENCRYPT},
        {"decrypt", ProgramOptions::COMMAND_TYPE::DECRYPT},
        {"checksum", ProgramOptions::COMMAND_TYPE::CHECKSUM},
    };

    bool isHelpRequested_;
    std::string inputFile_;
    std::string outputFile_;
    std::string password_;

    boost::program_options::options_description desc_;
};

}  // namespace CryptoGuard
