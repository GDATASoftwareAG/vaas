// A header-only library for reading information from (upper item having higher priority):
// - Command-line parameters (in the form: `--VAR_NAME=VALUE`, or `--VAR_NAME`)
// - .env file
// - Environment variables
//
// Dao Trung Kien
// https://github.com/daotrungkien


#include <iostream>
#include <fstream>
#include <string>
#include <map>
#include <algorithm>

#ifdef _WIN32
#include <Windows.h>
#elif __linux__
#include <limits.h>
#include <unistd.h>
#elif
#pragma message("dotenv::in_program_folder() is not supported on your platform.")
#endif


class dotenv {
public:
    enum class source { any, command_line, dotenv_file, environment };

protected:
    std::multimap<std::pair<std::string, source>, std::string> variables;

    static std::string trim(const std::string& s) {
        auto wsfront = std::find_if_not(s.begin(), s.end(), [](char c) { return std::isspace(c); });
        auto wsback = std::find_if_not(s.rbegin(), s.rend(), [](char c) { return std::isspace(c); }).base();
        return (wsback <= wsfront ? std::string() : std::string(wsfront, wsback));
    }

    void read_variable(const std::string& s, source var_source) {
        auto pos = s.find('=');
        if (pos > 0) {
            std::string name = trim(s.substr(0, pos));
            std::string value = s.substr(pos + 1);  // value is not trimed, leading and trailing spaces are kept
            if (!name.empty()) variables.emplace(std::make_pair(std::make_pair(name, var_source), value));
        } else {
            std::string name = trim(s);
            if (!name.empty()) variables.emplace(std::make_pair(std::make_pair(name, var_source), std::string()));
        }
    }

    void read_command_line(int argc, const char** argv) {
        for (int i = 1; i < argc; i++) {    // i starts from 1 to skip the first argument which is the command itself
            std::string s = argv[i];
            if (s.substr(0, 2) != "--") continue;

            read_variable(s.substr(2), source::command_line);
        }
    }

    void read_dotenv_file(const std::string& dotenv_path) {
        std::ifstream file(dotenv_path, std::ios::in);

        std::string s;
        while (std::getline(file, s)) {
            read_variable(s, source::dotenv_file);
        }
    }

    static bool my_getenv(const std::string& name, std::string& value) {
#ifdef _WIN32
        char* buf = nullptr;
        size_t sz = 0;
        if (_dupenv_s(&buf, &sz, name.c_str()) == 0 && buf != nullptr) {
            value = buf;
            free(buf);
            return true;
        }
#else
        const char* buf = std::getenv(name.c_str());
        if (buf) {
            value = buf;
            return true;
        }
#endif

        return false;
    }

public:
    dotenv(
            int argc = 0, const char** argv = nullptr,
            bool env_vars = true,
            const std::initializer_list<std::string> dotenv_paths = {
                    dotenv::in_current_folder(".env"),
                    dotenv::in_program_folder(".env")
            })
    {
        if (argc > 0) read_command_line(argc, argv);

        for (auto& path : dotenv_paths)
            if (!path.empty()) read_dotenv_file(path);
    }


    dotenv(int argc, const char** argv, bool env_vars, const std::string& dotenv_path) {
        if (argc > 0) read_command_line(argc, argv);

        if (!dotenv_path.empty()) read_dotenv_file(dotenv_path);
    }


    // checks if a variable exists in the selected source(s)
    bool exists(const std::string& name, source var_source = source::any) const {
        if (var_source == source::any || var_source == source::command_line) {
            auto itr_cmdline = variables.find(std::make_pair(name, source::command_line));
            if (itr_cmdline != variables.end()) return true;
        }

        if (var_source == source::any || var_source == source::dotenv_file) {
            auto itr_dotenv = variables.find(std::make_pair(name, source::dotenv_file));
            if (itr_dotenv != variables.end()) return true;
        }

        if (var_source == source::any || var_source == source::environment) {
            std::string value;
            if (my_getenv(name, value)) return true;
        }

        return false;
    }


    // returns the value of a variable if it exists in the selected source(s),
    // or a given default-valued string if it does not exist
    std::string get(const std::string& name, const std::string& default_value = std::string(), source var_source = source::any) const {
        if (var_source == source::any || var_source == source::command_line) {
            auto itr_cmdline = variables.find(std::make_pair(name, source::command_line));
            if (itr_cmdline != variables.end()) return itr_cmdline->second;
        }

        if (var_source == source::any || var_source == source::dotenv_file) {
            auto itr_dotenv = variables.find(std::make_pair(name, source::dotenv_file));
            if (itr_dotenv != variables.end()) return itr_dotenv->second;
        }

        if (var_source == source::any || var_source == source::environment) {
            std::string value;
            if (my_getenv(name, value)) return value;
        }

        return default_value;
    }


    // returns the value of a variable if it exists in the selected source(s),
    // or an empty string if it does not exist
    std::string get(const std::string& name, source var_source) const {
        return get(name, std::string(), var_source);
    }


    // returns the value of a variable if it exists in any of the sources,
    // or an empty string if it does not exist
    std::string operator[](const std::string& name) const {
        return get(name, std::string(), source::any);
    }


    static std::string get_program_path() {
#ifdef _WIN32
        char exe_path[MAX_PATH];
        return std::string(exe_path, GetModuleFileNameA(NULL, exe_path, MAX_PATH));
#elif __linux__
        char exe_path[PATH_MAX];
        std::size_t count = readlink("/proc/self/exe", exe_path, PATH_MAX);
        return std::string(exe_path, count > 0 ? count : 0);
#else
        throw std::runtime_error("dovenv");
#endif
    }

    static std::string get_program_folder() {
        std::string exe_path = get_program_path();

        std::size_t last_slash_idx = exe_path.rfind('\\');
        if (std::string::npos == last_slash_idx) last_slash_idx = exe_path.rfind('/');
        if (std::string::npos == last_slash_idx) return std::string();

        return exe_path.substr(0, last_slash_idx);
    }

    static std::string in_current_folder(const std::string& relative_file_path = std::string(".env")) {
        return relative_file_path;
    }

    static std::string in_program_folder(const std::string& relative_file_path = std::string(".env")) {
        return get_program_folder() + "/" + relative_file_path;
    }
};
