#ifndef VAAS_H
#define VAAS_H
#include <curl/curl.h>
#include <json/json.h>
#include <iostream>
#include <fstream>
#include <string>
#include <mutex>
#include <chrono>
#include <filesystem>
#include <utility>

namespace vaas_internals {

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

    curl_slist* raw() {
        return headers;
    }

private:
    curl_slist* headers = nullptr;
};

static size_t WriteAppendToString(void* contents, size_t size, size_t nmemb, void* userp) {
    static_cast<std::string*>(userp)->append(static_cast<char*>(contents), size * nmemb);
    return size * nmemb;
}

static long GetServerResponse(CURL* curl, Json::Value& jsonResponse) {
    std::string response;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, vaas_internals::WriteAppendToString);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        throw std::runtime_error("CURL request failed: " + std::string(curl_easy_strerror(res)));
    }

    long response_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

    Json::CharReaderBuilder readerBuilder;
    std::string errs;

    std::unique_ptr<Json::CharReader> reader(readerBuilder.newCharReader());
    if (!response.empty()) {
        if (!reader->parse(response.c_str(), response.c_str() + response.size(), &jsonResponse, &errs)) {
            throw std::runtime_error("Failed to parse JSON response: " + errs);
        }
    } else {
        // TODO
        std::cout << "got empty reply from server " << std::endl;
    }

    return response_code;
}

}

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

    std::string getAccessToken() {
        std::lock_guard lock(mtx);
        auto now = std::chrono::system_clock::now();
        if (now < tokenExpiry) {
            return accessToken;
        }

        curl_easy_reset(curl);

        vaas_internals::CurlHeaders headers;
        headers.append("Content-Type: application/x-www-form-urlencoded");

        std::string postFields = "grant_type=client_credentials&client_id=" + clientId + "&client_secret=" + clientSecret;

        curl_easy_setopt(curl, CURLOPT_URL, tokenEndpoint.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.raw());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postFields.c_str());

        Json::Value jsonResponse;
        auto response_code = vaas_internals::GetServerResponse(curl, jsonResponse);

        if (!(response_code == 200 || response_code == 401)) {
            throw std::runtime_error("Server replied with unexpected HTTP response code " + response_code);
        }

        if (jsonResponse.isMember("error") || response_code != 200) {
            auto errorMsg = jsonResponse.isMember("error_description")
                                ? jsonResponse.get("error_description", "")
                                : jsonResponse.get("error", "unknown error");
            throw std::runtime_error(errorMsg.asString());
        }

        accessToken = jsonResponse["access_token"].asString();
        int expiresIn = jsonResponse["expires_in"].asInt();
        tokenExpiry = now + std::chrono::seconds(expiresIn);

        return accessToken;
    }

private:
    std::string tokenEndpoint;
    std::string clientId;
    std::string clientSecret;

    std::string accessToken;
    std::chrono::system_clock::time_point tokenExpiry = std::chrono::system_clock::time_point::min();

    CURL* curl;
    std::mutex mtx;
};

class Vaas {
public:
    Vaas(std::string serverEndpoint, const std::string& tokenEndpoint, const std::string& clientId, const std::string& clientSecret)
        : serverEndpoint(std::move(serverEndpoint)), authenticator(tokenEndpoint, clientId, clientSecret), curl(curl_easy_init()) {
        if (!curl) {
            throw std::runtime_error("Failed to initialize CURL");
        }
    }

    ~Vaas() {
        if (curl) {
            curl_easy_cleanup(curl);
        }
    }

    void forFile(const std::filesystem::path& filePath) {
        const auto size = file_size(filePath);
        std::ifstream stream(filePath);
        forStream(stream, size);
    }

    void forStream(std::ifstream& stream, size_t fileSize) {
        auto token = authenticator.getAccessToken();

        curl_easy_reset(curl);

        vaas_internals::CurlHeaders headers;
        headers.append("Content-Type: application/octet-stream");

        auto url = serverEndpoint.append("/files");
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.raw());
        curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BEARER);
        curl_easy_setopt(curl, CURLOPT_XOAUTH2_BEARER, token.c_str());
        curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
        curl_easy_setopt(curl, CURLOPT_READDATA, &stream);
        curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, fileSize);
        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

        Json::Value jsonResponse;
        auto response_code = vaas_internals::GetServerResponse(curl, jsonResponse);

        std::cout << response_code << std::endl;
        std::cout << jsonResponse << std::endl;
    }

private:
    std::string serverEndpoint;
    OIDCClient authenticator;

    CURL* curl;
    std::mutex mtx;

    static size_t read_callback(char* ptr, size_t size, size_t nmemb, void* userp) {
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
};
#endif //VAAS_H