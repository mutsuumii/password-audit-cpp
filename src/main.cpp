#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cmath>
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <openssl/evp.h>

double entropy(const std::string& pw) {
    int charset = 0;
    bool has_lower = false, has_upper = false, has_digit = false, has_special = false;
    for (char c : pw) {
        if (std::islower(c)) has_lower = true;
        else if (std::isupper(c)) has_upper = true;
        else if (std::isdigit(c)) has_digit = true;
        else has_special = true;
    }
    if (has_lower) charset += 26;
    if (has_upper) charset += 26;
    if (has_digit) charset += 10;
    if (has_special) charset += 33;
    if (charset == 0) return 0.0;
    return pw.size() * std::log2(charset);
}

std::vector<std::string> check_patterns(const std::string& pw) {
    std::vector<std::string> issues;
    if (pw.size() < 8) issues.push_back("Length < 8");
    if (pw.size() < 12) issues.push_back("Recommended: 12+ chars");

    bool all_lower = true, all_digit = true;
    for (char c : pw) {
        if (!std::islower(c)) all_lower = false;
        if (!std::isdigit(c)) all_digit = false;
    }
    if (all_lower && !pw.empty()) issues.push_back("Lowercase only");
    if (all_digit && !pw.empty()) issues.push_back("Digits only");

    for (size_t i = 0; i + 2 < pw.size(); i++) {
        if (pw[i] == pw[i+1] && pw[i+1] == pw[i+2]) {
            issues.push_back("Repeated characters");
            break;
        }
    }

    std::string lower_pw = pw;
    std::transform(lower_pw.begin(), lower_pw.end(), lower_pw.begin(), ::tolower);
    const char* weak[] = {"qwerty", "12345", "abcdef", "password", "admin"};
    for (auto seq : weak) {
        if (lower_pw.find(seq) != std::string::npos) {
            issues.push_back(std::string("Contains: ") + seq);
        }
    }
    return issues;
}

std::string sha1_hex(const std::string& pw) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha1(), nullptr);
    EVP_DigestUpdate(ctx, pw.c_str(), pw.size());
    EVP_DigestFinal_ex(ctx, hash, &len);
    EVP_MD_CTX_free(ctx);

    std::ostringstream oss;
    for (unsigned int i = 0; i < len; i++)
        oss << std::hex << std::setfill('0') << std::setw(2) << (int)hash[i];
    return oss.str();
}

void audit(const std::string& pw) {
    double ent = entropy(pw);
    auto issues = check_patterns(pw);
    const char* strength = (ent >= 60.0 && issues.empty()) ? "STRONG"
                         : (ent >= 40.0) ? "MEDIUM" : "WEAK";
    auto h = sha1_hex(pw);

    std::cout << "\n" << std::string(50, '=') << "\n";
    std::cout << "Password: " << std::string(pw.size(), '*') << "\n";
    std::cout << "Length:   " << pw.size() << "\n";
    std::cout << "Entropy:  " << std::fixed << std::setprecision(2) << ent << " bits\n";
    std::cout << "Strength: " << strength << "\n";
    if (!issues.empty()) {
        std::cout << "Issues:\n";
        for (auto& i : issues) std::cout << "  - " << i << "\n";
    }
    std::string upper_h = h;
    std::transform(upper_h.begin(), upper_h.end(), upper_h.begin(), ::toupper);
    std::cout << "HIBP:     Prefix: " << upper_h.substr(0, 5)
              << ", Suffix: " << upper_h.substr(5) << "\n";
}

int main(int argc, char* argv[]) {
    if (argc > 1 && std::string(argv[1]) == "-f" && argc > 2) {
        std::ifstream f(argv[2]);
        std::string line;
        while (std::getline(f, line)) {
            if (!line.empty()) audit(line);
        }
    } else if (argc > 1) {
        audit(argv[1]);
    } else {
        std::cout << "Enter password: ";
        std::string pw;
        std::getline(std::cin, pw);
        audit(pw);
    }
    return 0;
}
