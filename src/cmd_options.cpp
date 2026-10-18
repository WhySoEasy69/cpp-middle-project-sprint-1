#include "cmd_options.h"
#include <exception>
#include <stdexcept>

namespace po = boost::program_options;

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : isHelpRequested_(false), desc_("Allowed options") {
    auto setParsedCommandFunc = [this](const std::string &command) { SetParsedCommand(command); };

    desc_.add_options()("help", "lists available options")(
        "command", po::value<std::string>()->notifier(setParsedCommandFunc),
        "command to execute")("input", po::value<std::string>(&inputFile_), "path to the input file")(
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
        // TODO: make more informative message, provide possible command option values.
        throw std::invalid_argument("Unsupported command");
    }
    command_ = it->second;
}

void ProgramOptions::Validate(const po::variables_map &vm) {
    if (vm.size() == 0) {
        throw std::invalid_argument("Empty options list specified");
    }

    // TODO: implement enum for command line arguments
    auto specifiedCommandsCount = 0;
    auto requiredCommands = {"input", "output", "password", "command"};
    for (const auto &command : requiredCommands) {
        if (vm.count(command) != 0) {
            ++specifiedCommandsCount;
        }
    }

    if (isHelpRequested_ && specifiedCommandsCount != 0) {
        throw std::invalid_argument("Extra options provided with --help. Use ./your_binary --help");
    } else if (!isHelpRequested_ && specifiedCommandsCount != requiredCommands.size()) {
        // TODO: provide required options str
        throw std::invalid_argument("Need to specify all required options. Required options: ...");
    }
}

}  // namespace CryptoGuard
