#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <expected>
#include <format>
#include <functional>
#include <print>
#include <ranges>
#include <regex>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace security::password {

enum class StrengthLevel : std::uint8_t {
    VERY_WEAK = 0,
    WEAK = 1,
    FAIR = 2,
    GOOD = 3,
    STRONG = 4,
    VERY_STRONG = 5
};

struct TransparentStringHasher {
    using is_transparent = void;
    
    [[nodiscard]] auto operator()(std::string_view sv) const noexcept -> std::size_t {
        return std::hash<std::string_view>{}(sv);
    }
    
    [[nodiscard]] auto operator()(const std::string& s) const noexcept -> std::size_t {
        return std::hash<std::string>{}(s);
    }
    
    [[nodiscard]] auto operator()(const char* s) const noexcept -> std::size_t {
        return std::hash<std::string_view>{}(std::string_view{s});
    }
};

using TransparentStringSet = std::unordered_set<std::string, TransparentStringHasher, std::equal_to<>>;

struct SecurityAnalysis final {
    std::vector<std::string> vulnerabilities;
    std::vector<std::string> threats;
    std::uint8_t risk_score{0};
};

struct ComplexityAnalysis final {
    double entropy_value{0.0};
    double pattern_strength{0.0};
    double uniqueness_factor{0.0};
};

struct ComplianceMetrics final {
    std::uint8_t nist_score{0};
    double standard_compliance{0.0};
    bool meets_requirements{false};
};

struct AnalysisResult final {
    StrengthLevel level{StrengthLevel::VERY_WEAK};
    ComplexityAnalysis complexity;
    SecurityAnalysis security;
    ComplianceMetrics compliance;
    double estimated_crack_time{0.0};
    std::vector<std::string> improvement_recommendations;
    
    [[nodiscard]] constexpr auto strength_name() const noexcept -> std::string_view {
        constexpr std::array names{
            "Very Weak", "Weak", "Fair", "Good", "Strong", "Very Strong"
        };
        const auto index = std::to_underlying(level);
        return names[static_cast<std::size_t>(index)];
    }
    
    [[nodiscard]] auto generate_report() const -> std::string {
        std::string report_content;
        report_content += "{\n";
        report_content += "  \"strength_level\": " + std::to_string(std::to_underlying(level)) + ",\n";
        report_content += "  \"level_name\": \"" + std::string(strength_name()) + "\",\n";
        report_content += "  \"entropy_bits\": " + std::to_string(complexity.entropy_value) + ",\n";
        report_content += "  \"crack_time_seconds\": " + std::to_string(estimated_crack_time) + ",\n";
        
        report_content += "  \"security_issues\": [";
        for (std::size_t i = 0; i < security.vulnerabilities.size(); ++i) {
            if (i > 0) report_content += ", ";
            report_content += "\"" + security.vulnerabilities[i] + "\"";
        }
        report_content += "],\n";
        
        report_content += "  \"recommendations\": [";
        for (std::size_t i = 0; i < improvement_recommendations.size(); ++i) {
            if (i > 0) report_content += ", ";
            report_content += "\"" + improvement_recommendations[i] + "\"";
        }
        report_content += "],\n";
        
        report_content += "  \"nist_compliance\": " + std::to_string(compliance.nist_score) + "\n";
        report_content += "}";
        
        return report_content;
    }
};

class ComplexityAnalyzer final {
private:
    static constexpr double BASELINE_ENTROPY{10.0};
    static constexpr double MAXIMUM_ENTROPY{120.0};
    
public:
    [[nodiscard]] auto evaluate_complexity(std::string_view password) const noexcept -> ComplexityAnalysis {
        ComplexityAnalysis analysis;
        
        const auto character_diversity = calculate_character_diversity(password);
        const auto length_factor = calculate_length_contribution(password);
        const auto randomness_score = assess_randomness_level(password);
        
        analysis.entropy_value = character_diversity + length_factor + randomness_score;
        analysis.pattern_strength = evaluate_pattern_resistance(password);
        analysis.uniqueness_factor = calculate_uniqueness_score(password);
        
        analysis.entropy_value = std::clamp(analysis.entropy_value, 0.0, MAXIMUM_ENTROPY);
        
        return analysis;
    }

private:
    [[nodiscard]] auto calculate_character_diversity(std::string_view password) const noexcept -> double {
        int character_types = 0;
        bool has_lowercase = false;
        bool has_uppercase = false;
        bool has_numbers = false;
        bool has_symbols = false;
        
        for (std::size_t i = 0; i < password.length(); ++i) {
            const char current_char = password[i];
            if (current_char >= 'a' && current_char <= 'z') has_lowercase = true;
            if (current_char >= 'A' && current_char <= 'Z') has_uppercase = true;
            if (current_char >= '0' && current_char <= '9') has_numbers = true;
            if (!((current_char >= 'a' && current_char <= 'z') || 
                  (current_char >= 'A' && current_char <= 'Z') || 
                  (current_char >= '0' && current_char <= '9'))) {
                has_symbols = true;
            }
        }
        
        character_types += has_lowercase ? 26 : 0;
        character_types += has_uppercase ? 26 : 0;
        character_types += has_numbers ? 10 : 0;
        character_types += has_symbols ? 32 : 0;
        
        if (character_types == 0) character_types = 1;
        
        return std::log2(static_cast<double>(character_types)) * password.length();
    }
    
    [[nodiscard]] auto calculate_length_contribution(std::string_view password) const noexcept -> double {
        const double base_contribution = static_cast<double>(password.length()) * 1.5;
        if (password.length() >= 16) return base_contribution * 1.2;
        if (password.length() >= 12) return base_contribution * 1.1;
        if (password.length() >= 8) return base_contribution;
        return base_contribution * 0.7;
    }
    
    [[nodiscard]] auto assess_randomness_level(std::string_view password) const noexcept -> double {
        std::unordered_map<char, int> frequency_map;
        
        for (std::size_t i = 0; i < password.length(); ++i) {
            frequency_map[password[i]]++;
        }
        
        int max_frequency = 0;
        for (const auto& pair : frequency_map) {
            if (pair.second > max_frequency) {
                max_frequency = pair.second;
            }
        }
        
        const double repetition_ratio = static_cast<double>(max_frequency) / password.length();
        return BASELINE_ENTROPY * (1.0 - repetition_ratio);
    }
    
    [[nodiscard]] auto evaluate_pattern_resistance(std::string_view password) const noexcept -> double {
        double resistance_score = 1.0;
        
        // Check for keyboard sequences
        const std::string qwerty_row = "qwertyuiopasdfghjklzxcvbnm";
        const std::string number_row = "1234567890";
        
        resistance_score *= check_sequence_resistance(password, qwerty_row);
        resistance_score *= check_sequence_resistance(password, number_row);
        
        // Check for character sequences
        int sequential_count = 0;
        for (std::size_t i = 2; i < password.length(); ++i) {
            const int diff1 = password[i] - password[i-1];
            const int diff2 = password[i-1] - password[i-2];
            if (std::abs(diff1) == 1 && std::abs(diff2) == 1) {
                sequential_count++;
            }
        }
        
        if (sequential_count > 0) {
            const double penalty = static_cast<double>(sequential_count) / password.length();
            resistance_score *= (1.0 - penalty * 0.3);
        }
        
        return resistance_score;
    }
    
    [[nodiscard]] auto check_sequence_resistance(std::string_view password, 
                                               const std::string& sequence) const noexcept -> double {
        int longest_match = 0;
        int current_match = 0;
        
        for (std::size_t i = 0; i < password.length(); ++i) {
            const char lower_char = std::tolower(password[i]);
            const auto found_pos = sequence.find(lower_char);
            
            if (found_pos != std::string::npos && i > 0) {
                const char prev_lower = std::tolower(password[i-1]);
                const auto prev_pos = sequence.find(prev_lower);
                
                if (prev_pos != std::string::npos && 
                    (found_pos == prev_pos + 1 || found_pos == prev_pos - 1)) {
                    current_match++;
                } else {
                    longest_match = std::max(longest_match, current_match);
                    current_match = 1;
                }
            } else {
                longest_match = std::max(longest_match, current_match);
                current_match = found_pos != std::string::npos ? 1 : 0;
            }
        }
        
        longest_match = std::max(longest_match, current_match);
        
        if (longest_match <= 2) return 1.0;
        
        const double penalty = static_cast<double>(longest_match) / password.length();
        return 1.0 - (penalty * 0.4);
    }
    
    [[nodiscard]] auto calculate_uniqueness_score(std::string_view password) const noexcept -> double {
        // Simplified uniqueness calculation
        std::unordered_set<char> unique_chars;
        
        for (std::size_t i = 0; i < password.length(); ++i) {
            unique_chars.insert(password[i]);
        }
        
        const double uniqueness_ratio = static_cast<double>(unique_chars.size()) / password.length();
        return uniqueness_ratio;
    }
};

class SecurityAnalyzer final {
private:
    TransparentStringSet breach_database_;
    TransparentStringSet common_terms_;
    
public:
    explicit SecurityAnalyzer() {
        initialize_threat_databases();
    }
    
    [[nodiscard]] auto evaluate_security(std::string_view password) const -> SecurityAnalysis {
        SecurityAnalysis analysis;
        
        perform_breach_check(password, analysis);
        assess_common_patterns(password, analysis);
        evaluate_attack_vectors(password, analysis);
        
        analysis.risk_score = calculate_overall_risk(analysis);
        
        return analysis;
    }

private:
    void initialize_threat_databases() noexcept {
        breach_database_ = TransparentStringSet{
            "password", "123456", "123456789", "guest", "qwerty", "12345678", "111111",
            "12345", "col123456", "123123", "1234567", "1234", "1234567890", "000000",
            "555555", "666666", "123321", "654321", "7777777", "123", "password1",
            "1234560", "123456a", "qwertyuiop", "123qwe", "zxcvbnm", "121212",
            "asdasd", "a123456", "123456q", "admin", "welcome", "monkey", "dragon"
        };
        
        common_terms_ = TransparentStringSet{
            "password", "welcome", "monkey", "dragon", "master", "freedom", "whatever",
            "jordan", "secret", "summer", "flower", "shadow", "champion", "princess",
            "orange", "starwars", "computer", "michelle", "maggie", "jessica", "love",
            "hello", "angel", "sunshine", "password1", "football", "charlie", "lovely"
        };
    }
    
    void perform_breach_check(std::string_view password, SecurityAnalysis& analysis) const {
        std::string lowercase_password;
        lowercase_password.reserve(password.length());
        
        for (std::size_t i = 0; i < password.length(); ++i) {
            lowercase_password += static_cast<char>(std::tolower(password[i]));
        }
        
        if (breach_database_.contains(lowercase_password)) {
            analysis.vulnerabilities.emplace_back("Password found in breach databases");
            analysis.threats.emplace_back("High risk of credential stuffing attacks");
        }
        
        // Check for partial matches
        for (const auto& breach_term : breach_database_) {
            if (breach_term.length() >= 4 && lowercase_password.find(breach_term) != std::string::npos) {
                analysis.vulnerabilities.emplace_back("Contains known compromised password fragment");
                break;
            }
        }
    }
    
    void assess_common_patterns(std::string_view password, SecurityAnalysis& analysis) const {
        if (password.length() < 8) {
            analysis.vulnerabilities.emplace_back("Password length insufficient for security");
        }
        
        bool has_lower = false;
        bool has_upper = false;
        bool has_digit = false;
        bool has_special = false;
        
        for (std::size_t i = 0; i < password.length(); ++i) {
            const char c = password[i];
            if (c >= 'a' && c <= 'z') has_lower = true;
            if (c >= 'A' && c <= 'Z') has_upper = true;
            if (c >= '0' && c <= '9') has_digit = true;
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))) {
                has_special = true;
            }
        }
        
        if (!has_lower || !has_upper) {
            analysis.vulnerabilities.emplace_back("Lacks mixed case characters");
        }
        if (!has_digit) {
            analysis.vulnerabilities.emplace_back("Missing numeric characters");
        }
        if (!has_special) {
            analysis.vulnerabilities.emplace_back("No special characters present");
        }
    }
    
    void evaluate_attack_vectors(std::string_view password, SecurityAnalysis& analysis) const {
        // Dictionary word detection
        std::string lowercase_version;
        for (std::size_t i = 0; i < password.length(); ++i) {
            lowercase_version += static_cast<char>(std::tolower(password[i]));
        }
        
        for (const auto& common_word : common_terms_) {
            if (common_word.length() >= 4 && lowercase_version.find(common_word) != std::string::npos) {
                analysis.threats.emplace_back("Vulnerable to dictionary-based attacks");
                break;
            }
        }
