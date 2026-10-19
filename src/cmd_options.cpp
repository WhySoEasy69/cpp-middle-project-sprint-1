#include "cmd_options.h"
#include <boost/algorithm/string/join.hpp>
#include <boost/range/adaptor/map.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include <exception>
#include <sstream>
#include <stdexcept>

namespace po = boost::program_options;

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : isHelpRequested_(false), desc_("Allowed options") {
    auto setParsedCommandFunc = [this](const std::string &command) { SetParsedCommand(command); };

    auto possibleCommandsValuesStr =
        boost::algorithm::join(commandMapping_ | boost::adaptors::map_keys |
                                   boost::adaptors::transformed([](std::string_view sv) { return std::string(sv); }),
                               ", ");
    std::ostringstream oss;
    oss << "command to execute: " << possibleCommandsValuesStr;
    auto commandOptionDesc = oss.str();

    desc_.add_options()("help", "lists available options")(
        "command", po::value<std::string>()->notifier(setParsedCommandFunc),
        commandOptionDesc.c_str())("input", po::value<std::string>(&inputFile_), "path to the input file")(
        "output", po::value<std::string>(&outputFile_), "path to the output file")(
        "password", po::value<std::string>(&password_), "password for encrypting and decrypting");
}

void ProgramOptions::Parse(int argc, const char *const *argv) {
    po::variables_map vm;
    auto style = po::command_line_style::default_style & ~po::command_line_style::allow_guessing;
    po::positional_options_description p;
    po::store(po::command_line_parser(argc, argv).options(desc_).positional(p).style(style).run(), vm);
    po::notify(vm);

    if (vm.count("help")) {
        isHelpRequested_ = true;
    }

    Validate(vm);
}

void ProgramOptions::SetParsedCommand(const std::string &command) {
    auto it = commandMapping_.find(command);
    if (it == commandMapping_.end()) {
        throw std::invalid_argument("Unsupported command");
    }
    command_ = it->second;
}

void ProgramOptions::Validate(const po::variables_map &vm) {
    if (vm.size() == 0) {
        throw std::invalid_argument("Empty options list specified");
    }

    if (isHelpRequested_ && vm.size() != 1) {
        throw std::invalid_argument("Extra options provided with --help. Use ./your_binary --help");
    } else if (isHelpRequested_) {
        return;
    }

    if (vm.count("command") == 0) {
        throw std::invalid_argument("\'command\' options must be specified");
    }

    std::vector<std::string> requiredOptionsForCommand;
    if (command_ == COMMAND_TYPE::CHECKSUM) {
        requiredOptionsForCommand = {"input"};
    } else {
        requiredOptionsForCommand = {"input", "output", "password", "command"};
    }

    // TODO: implement enum for command line arguments
    auto specifiedOptionsCount = 0;
    for (const auto &option : requiredOptionsForCommand) {
        if (vm.count(option) != 0) {
            ++specifiedOptionsCount;
        }
    }

    auto commandStr = vm["command"].as<std::string>();
    if (requiredOptionsForCommand.size() > specifiedOptionsCount) {
        throw std::invalid_argument("Extra options provided for command \'" + commandStr + "\'");
    } else if (requiredOptionsForCommand.size() < specifiedOptionsCount) {
        auto requiredOptionsStr = boost::algorithm::join(requiredOptionsForCommand, ", ");
        std::ostringstream oss;
        oss << "Need to specify all required options for \'" << commandStr
            << "\' command. Required options: " << requiredOptionsStr;
        throw std::invalid_argument(oss.str());
    }

    if (command_ != COMMAND_TYPE::CHECKSUM && inputFile_ == outputFile_) {
        throw std::invalid_argument("\'input\' and \'output\' args values must be different");
    }
}

}  // namespace CryptoGuard
