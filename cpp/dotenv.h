/*
 * Very simple dotenv implementation in C++,
 * specifically for the use case of running tests in this repository.
 *
 * It tries to read `.env` file in the current directory or a custom file.
 * If no file is found, no error is thrown, instead the environment variable
 * is expected to be set in the environment.
 *
 * If both the file and the environment variable are set, the environment variable
 * takes precedence.
 */

#ifndef DOTENV_H
#define DOTENV_H

#include <algorithm>
#include <exception>
#include <filesystem>
#include <fstream>
#include <map>
#include <stdexcept>
#include <string>

namespace dotenv {

class Dotenv {
  private:
    std::string envFile;
    std::map<std::string, std::string> envFromFile;

    std::map<std::string, std::string> readEnvFromFile() {
        std::map<std::string, std::string> env;
        std::ifstream file(envFile);
        char charsToRemove[] = {'"', '\''};
        
        if (!file) {
            return env;
        }
        
        for (std::string line; std::getline(file, line);) {
            const auto pos = line.find('=');
            if (pos != std::string::npos) {
                const auto key = line.substr(0, pos);
                auto value = line.substr(pos + 1);

                removeCharsFromString(value, charsToRemove);

                env[key] = value;
            }
        }

        return env;
    }

    static void removeCharsFromString(std::string& str, char* charsToRemove) {
        for (unsigned int i = 0; i < sizeof(charsToRemove); ++i) {
            str.erase(remove(str.begin(), str.end(), charsToRemove[i]), str.end());
        }
    }

  public:
    Dotenv() : envFile(".env") {
        this->envFromFile = readEnvFromFile();
    };

    Dotenv(const std::string& envFile) : envFile(envFile) {
        this->envFromFile = readEnvFromFile();
    };

    std::string get(const std::string& key) {
        if (std::getenv(key.c_str())) {
            return std::getenv(key.c_str());
        }

        if (envFromFile.find(key) != envFromFile.end()) {
            return envFromFile[key];
        }

        throw std::runtime_error(key + " must be set");
    }
};

} // namespace dotenv
#endif // !DOTENV_H
