#include "cmd_options.h"
#include <gtest/gtest.h>
#include <utility>

using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
using OptoinsValuesMap = std::unordered_map<std::string, std::string>;

const OptoinsValuesMap validOptionsValues = {
    {"--input", "ifile"}, {"--output", "ofile"}, {"--command", "encrypt"}, {"--password", "123"}};

class ProgramArgs {
public:
    ProgramArgs(const OptoinsValuesMap &optionsValues) {
        storage_.reserve(optionsValues.size() + 1);
        storage_.push_back("./binary");
        for (const auto &[opt, val] : optionsValues) {
            storage_.push_back(opt);
            if (!val.empty()) {
                storage_.push_back(val);
            }
        }
        storage_.shrink_to_fit();

        argv_.reserve(storage_.size());
        for (const auto &el : storage_) {
            argv_.push_back(el.c_str());
        }
    }

    int argc() const { return static_cast<int>(argv_.size()); }

    const char *const *argv() const { return argv_.data(); }

private:
    std::vector<std::string> storage_;
    std::vector<const char *> argv_;
};

class TestInvalidOptionsParsingWithParams : public ::testing::TestWithParam<std::string> {};

TEST_P(TestInvalidOptionsParsingWithParams, MissingRequiredOption) {
    auto optionsValuesCopy = validOptionsValues;
    const auto &command = GetParam();
    optionsValuesCopy.erase(command);

    ProgramArgs args(optionsValuesCopy);
    CryptoGuard::ProgramOptions options;

    ASSERT_THROW(options.Parse(args.argc(), args.argv()), std::exception);
}

INSTANTIATE_TEST_SUITE_P(MissingCommandValues, TestInvalidOptionsParsingWithParams,
                         ::testing::Values("--input", "--output", "--password", "--command"));

TEST(TestInvalidOptionsParsing, UnknownOption) {
    auto optionsValuesCopy = validOptionsValues;
    optionsValuesCopy.insert({"--unknown_option", "value"});

    ProgramArgs args(optionsValuesCopy);
    CryptoGuard::ProgramOptions options;

    ASSERT_THROW(options.Parse(args.argc(), args.argv()), std::exception);
}

TEST(TestInvalidOptionsParsing, UnknownCryptoCommand) {
    auto optionsValuesCopy = validOptionsValues;
    optionsValuesCopy["--command"] = "unknown_command_value";

    ProgramArgs args(optionsValuesCopy);
    CryptoGuard::ProgramOptions options;

    ASSERT_THROW(options.Parse(args.argc(), args.argv()), std::exception);
}

TEST(TestInvalidOptionsParsing, EmptyOptionsList) {
    ProgramArgs args({});
    CryptoGuard::ProgramOptions options;

    ASSERT_THROW(options.Parse(args.argc(), args.argv()), std::exception);
}

TEST(TestInvalidOptionsParsing, HelpOptionExtraValue) {
    auto optionsValuesCopy = validOptionsValues;
    optionsValuesCopy["--help"] = "extra_help_value";

    ProgramArgs args(optionsValuesCopy);
    CryptoGuard::ProgramOptions options;

    ASSERT_THROW(options.Parse(args.argc(), args.argv()), std::exception);
}

TEST(TestInvalidOptionsParsing, HelpWithExtraOptions) {
    auto optionsValuesCopy = validOptionsValues;
    optionsValuesCopy["--help"] = "";

    ProgramArgs args(optionsValuesCopy);
    CryptoGuard::ProgramOptions options;

    ASSERT_THROW(options.Parse(args.argc(), args.argv()), std::exception);
}

TEST(TestSuccessfulOptionsParsing, ValidHelpUsage) {
    OptoinsValuesMap optionsValues = {{"--help", ""}};

    ProgramArgs args(optionsValues);
    CryptoGuard::ProgramOptions options;

    options.Parse(args.argc(), args.argv());

    EXPECT_EQ(options.IsHelpRequested(), true);
}

struct TestCommandValue {
    std::string commandStr_;
    COMMAND_TYPE expectedValue_;
};

class TestSuccessfulOptionsParsingWithParams : public ::testing::TestWithParam<TestCommandValue> {};

TEST_P(TestSuccessfulOptionsParsingWithParams, ValidCryptoCommandsUsage) {
    auto optionsValuesCopy = validOptionsValues;
    auto &param = GetParam();
    optionsValuesCopy["--command"] = std::move(param.commandStr_);

    ProgramArgs args(optionsValuesCopy);
    CryptoGuard::ProgramOptions options;
    options.Parse(args.argc(), args.argv());

    EXPECT_EQ(options.IsHelpRequested(), false);
    EXPECT_EQ(options.GetInputFile(), optionsValuesCopy["--input"]);
    EXPECT_EQ(options.GetOutputFile(), optionsValuesCopy["--output"]);
    EXPECT_EQ(options.GetPassword(), optionsValuesCopy["--password"]);
    EXPECT_EQ(options.GetCommand(), param.expectedValue_);
}

INSTANTIATE_TEST_SUITE_P(CommandValues, TestSuccessfulOptionsParsingWithParams,
                         ::testing::Values(TestCommandValue{"encrypt", COMMAND_TYPE::ENCRYPT},
                                           TestCommandValue{"decrypt", COMMAND_TYPE::DECRYPT},
                                           TestCommandValue{"checksum", COMMAND_TYPE::CHECKSUM}));