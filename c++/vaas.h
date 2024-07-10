#ifndef VAAS_H
#define VAAS_H
#include <chrono>
#include <curl/curl.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <json/json.h>
#include <mutex>
#include <string>
#include <utility>

namespace vaas {

/// An AuthenticationException indicates that the credentials are incorrect. Manual intervention may be required.
class AuthenticationException final : public std::runtime_error {
  public:
    using std::runtime_error::runtime_error;
};

/// A VaasException indicates that an I/O error occured while communicating with the VaaS service. The client may retry at a later time.
class VaasException final : public std::runtime_error {
    using std::runtime_error::runtime_error;
};

} // namespace vaas

namespace vaas_internals {

// TODO: Move to settings block
static const char* USER_AGENT = "C++ SDK 0.1.0";

static void ensureCurlOk(CURLcode code) {
    if (code != CURLE_OK) {
        throw vaas::VaasException("CURL request failed: " + std::string(curl_easy_strerror(code)));
    }
}

static void resetCurl(CURL* curl) {
    curl_easy_reset(curl);
    ensureCurlOk(curl_easy_setopt(curl, CURLOPT_USERAGENT, vaas_internals::USER_AGENT));
    // TODO: Use setting from settings block
    // ensureCurlOk(curl_easy_setopt(curl, CURLOPT_VERBOSE, 1));
}

class CurlHeaders {
  public:
    CurlHeaders() = default;
    CurlHeaders(const CurlHeaders&) = delete;

    ~CurlHeaders() {
        if (headers) {
            curl_slist_free_all(headers);
            headers = nullptr;
        }
    }

    void append(const char* data) {
        headers = curl_slist_append(headers, data);
    }

    [[nodiscard]] curl_slist* raw() const {
        return headers;
    }

  private:
    curl_slist* headers = nullptr;
};

static size_t writeAppendToString(void* contents, const size_t size, const size_t nmemb, void* userp) {
    static_cast<std::string*>(userp)->append(static_cast<char*>(contents), size * nmemb);
    return size * nmemb;
}

static long getServerResponse(CURL* curl, Json::Value& jsonResponse) {
    std::string response;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, vaas_internals::writeAppendToString);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    const CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        throw vaas::VaasException("CURL request failed: " + std::string(curl_easy_strerror(res)));
    }

    long response_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

    // TODO if !(200 <= response_code < 300)

    const Json::CharReaderBuilder readerBuilder;
    std::string errs;

    const std::unique_ptr<Json::CharReader> reader(readerBuilder.newCharReader());
    if (!response.empty()) {
        if (!reader->parse(response.c_str(), response.c_str() + response.size(), &jsonResponse, &errs)) {
            throw vaas::VaasException("Failed to parse JSON response: " + errs);
        }
    }

    return response_code;
}

} // namespace vaas_internals

namespace vaas {

/// The OIDCClient is responsible for obtaining OAuth tokens from an identity provider. These are used to authenticate against the VaaS API.
class OIDCClient {
  public:
    OIDCClient(std::string tokenEndpoint, std::string clientId, std::string clientSecret)
        : tokenEndpoint(std::move(tokenEndpoint)), clientId(std::move(clientId)), clientSecret(std::move(clientSecret)), curl(curl_easy_init()) {
        if (!curl) {
            throw std::runtime_error("Failed to initialize CURL");
        }
    }

    ~OIDCClient() {
        if (curl) {
            curl_easy_cleanup(curl);
        }
    }

    /// <summary>
    /// Retrieve a new access token from the identity provider, or return a cached token that is still valid.
    /// </summary>
    std::string getAccessToken() {
        std::lock_guard lock(mtx);
        const auto now = std::chrono::system_clock::now();
        if (now < tokenExpiry) {
            return accessToken;
        }

        curl_easy_reset(curl);

        vaas_internals::CurlHeaders headers;
        headers.append("Content-Type: application/x-www-form-urlencoded");

        const std::string postFields = "grant_type=client_credentials&client_id=" + clientId + "&client_secret=" + clientSecret;

        curl_easy_setopt(curl, CURLOPT_URL, tokenEndpoint.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.raw());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postFields.c_str());

        Json::Value jsonResponse;

        const auto response_code = vaas_internals::getServerResponse(curl, jsonResponse);
        if (!(response_code == 200 || response_code == 401)) {
            throw AuthenticationException("Server replied with unexpected HTTP response code " + std::to_string(response_code));
        }

        if (jsonResponse.isMember("error") || response_code != 200) {
            const auto errorMsg = jsonResponse.isMember("error_description")
                                      ? jsonResponse.get("error_description", "")
                                      : jsonResponse.get("error", "unknown error");
            throw AuthenticationException(errorMsg.asString());
        }

        accessToken = jsonResponse["access_token"].asString();
        const int expiresIn = jsonResponse["expires_in"].asInt();
        tokenExpiry = now + std::chrono::seconds(expiresIn);

        return accessToken;
    }

  private:
    const std::string tokenEndpoint;
    const std::string clientId;
    const std::string clientSecret;

    std::string accessToken;
    std::chrono::system_clock::time_point tokenExpiry = std::chrono::system_clock::time_point::min();

    CURL* curl;
    std::mutex mtx;
};

/// VaasReport contains an analysis report for a file, such as verdict information.
class VaasReport {
    const std::string sha256;

    enum Verdict {
        Clean = 0,
        Malicious,
        Pup,
        Unknown
    };

    Verdict verdict;

    static std::string verdictToString(const Verdict verdict) noexcept {
        // Keep in same order as enum declaration
        static const std::string ENUM_STRINGS[] = {"Clean", "Malicious", "Pup", "Unknown"};
        return ENUM_STRINGS[verdict];
    }

  protected:
    friend class Vaas;
    friend std::ostream& operator<<(std::ostream& os, const VaasReport& report);

    explicit VaasReport(const Json::Value& raw) : sha256{raw.get("sha256", "NULL").as<std::string>()} {
        const auto verdictRaw = raw.get("verdict", "NULL").as<std::string>();
        verdict = Unknown;
        if (verdictRaw == "Clean")
            verdict = Clean;
        if (verdictRaw == "Malicious")
            verdict = Malicious;
        if (verdictRaw == "Pup")
            verdict = Pup;
    }
};

inline std::ostream& operator<<(std::ostream& os, const VaasReport& report) {
    os << "sha256: " << report.sha256 << " verdict: " << VaasReport::verdictToString(report.verdict);
    return os;
}

/// Vaas talks to the VaaS service and provides reports for files or streams.
class Vaas {
  public:
    Vaas(std::string serverEndpoint, const std::string& tokenEndpoint, const std::string& clientId, const std::string& clientSecret)
        : serverEndpoint(serverEndpoint), authenticator(tokenEndpoint, clientId, clientSecret), curl(curl_easy_init()) {
        if (!curl) {
            throw std::runtime_error("Failed to initialize CURL");
        }
    }

    ~Vaas() {
        if (curl) {
            curl_easy_cleanup(curl);
        }
    }

    /// <summary>
    /// Open the provided filepath and send it to VaaS for analysis. Returns the report of the anaylzed file.
    /// </summary>
    VaasReport forFile(const std::filesystem::path& filePath) {
        const auto size = file_size(filePath);
        std::ifstream stream(filePath);
        return forStream(stream, size);
    }

    /// <summary>
    /// Use the provided ifstream and send it to VaaS for analysis. Returns the report of the anaylzed file.
    /// </summary>
    VaasReport forStream(std::ifstream& stream, const size_t fileSize) {
        // TODO: Check hash first
        const auto resultUrl = upload(stream, fileSize);
        return pollReport(resultUrl);
    }

  private:
    const std::string serverEndpoint;
    OIDCClient authenticator;

    CURL* curl;
    std::mutex mtx;

    static size_t readCallback(char* ptr, const size_t size, const size_t nmemb, void* userp) {
        auto* currentFile = static_cast<std::ifstream*>(userp);
        if (currentFile->eof()) {
            return 0;
        }
        if (currentFile->fail()) {
            return CURL_READFUNC_ABORT;
        }
        currentFile->read(ptr, static_cast<std::streamsize>(size * nmemb));
        return currentFile->gcount();
    }

    std::string upload(std::ifstream& stream, const size_t fileSize) {
        const auto token = authenticator.getAccessToken();

        vaas_internals::resetCurl(curl);

        vaas_internals::CurlHeaders headers;
        headers.append("Content-Type: application/octet-stream");

        const auto url = serverEndpoint + "/files";
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.raw());
        curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BEARER);
        curl_easy_setopt(curl, CURLOPT_XOAUTH2_BEARER, token.c_str());
        curl_easy_setopt(curl, CURLOPT_READFUNCTION, readCallback);
        curl_easy_setopt(curl, CURLOPT_READDATA, &stream);
        curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, fileSize);
        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

        Json::Value jsonResponse;
        const auto response_code = vaas_internals::getServerResponse(curl, jsonResponse);

        if (response_code != 201) {
            throw VaasException("Unexpected HTTP response code " + std::to_string(response_code));
        }

        curl_header* location_header;
        if (const CURLHcode err = curl_easy_header(curl, "Location", 0, CURLH_HEADER, -1, &location_header); err != CURLHE_OK) {
            throw VaasException("No location header found for 201 response");
        }
        const auto location = std::string(location_header->value);
        return serverEndpoint + location;
    }

    VaasReport pollReport(const std::string& fileUrl) {
        while (true) {
            auto token = authenticator.getAccessToken();

            vaas_internals::resetCurl(curl);

            std::string reportUrl = fileUrl + "/report";
            curl_easy_setopt(curl, CURLOPT_URL, reportUrl.c_str());
            curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BEARER);
            curl_easy_setopt(curl, CURLOPT_XOAUTH2_BEARER, token.c_str());

            Json::Value jsonResponse;
            const auto response_code = vaas_internals::getServerResponse(curl, jsonResponse);

            if (!(response_code == 200 || response_code == 202)) {
                throw VaasException("Unexpected HTTP response code " + std::to_string(response_code));
            }

            if (response_code == 200) {
                return VaasReport(jsonResponse);
            }
        }
    }
};

} // namespace vaas
#endif // VAAS_H