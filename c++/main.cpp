#include <iostream>
#include <string>
#include <mutex>
#include <chrono>
#include <curl/curl.h>
#include <json/json.h>

class OIDCClient {
public:
    OIDCClient(const std::string& tokenEndpoint, const std::string& clientId, const std::string& clientSecret)
        : tokenEndpoint(tokenEndpoint), clientId(clientId), clientSecret(clientSecret), curl(curl_easy_init()) {
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
        std::lock_guard<std::mutex> lock(mtx);

        auto now = std::chrono::system_clock::now();
        if (now < tokenExpiry) {
            return accessToken;
        }

        CURLcode res;
        curl_easy_reset(curl);

        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");

        std::string postFields = "grant_type=client_credentials&client_id=" + clientId + "&client_secret=" + clientSecret;

        curl_easy_setopt(curl, CURLOPT_URL, tokenEndpoint.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postFields.c_str());

        std::string response;
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        res = curl_easy_perform(curl);

        curl_slist_free_all(headers);

        if (res != CURLE_OK) {
            throw std::runtime_error("CURL request failed: " + std::string(curl_easy_strerror(res)));
        }

        Json::CharReaderBuilder readerBuilder;
        Json::Value jsonResponse;
        std::string errs;

        std::unique_ptr<Json::CharReader> reader(readerBuilder.newCharReader());
        if (!reader->parse(response.c_str(), response.c_str() + response.size(), &jsonResponse, &errs)) {
            throw std::runtime_error("Failed to parse JSON response: " + errs);
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

    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
        ((std::string*)userp)->append((char*)contents, size * nmemb);
        return size * nmemb;
    }
};

int main() {
    try {
        OIDCClient client("https://example.com/token", "client_id", "client_secret");
        std::string token = client.getAccessToken();
        std::cout << "Access Token: " << token << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}
