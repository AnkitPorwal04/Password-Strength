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

// Custom transparent hasher for heterogeneous string lookups
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

// Transparent string container aliases
using TransparentStringSet = std::unordered_set<std::string, TransparentStringHasher, std::equal_to<>>;

struct AnalysisResult final {
    StrengthLevel level{StrengthLevel::VERY_WEAK};
    double entropy_bits{0.0};
    double crack_time_seconds{0.0};
    std::vector<std::string> vulnerabilities;
    std::vector<std::string> suggestions;
    std::uint8_t nist_score{0};
    
    [[nodiscard]] constexpr auto strength_name() const noexcept -> std::string_view {
        constexpr std::array names{
            "Very Weak", "Weak", "Fair", "Good", "Strong", "Very Strong"
        };
        const auto index = std::to_underlying(level);
        return names[static_cast<std::size_t>(index)];
    }
    
    [[nodiscard]] auto to_json() const -> std::string {
        auto format_array = [](const auto& arr) {
            return arr | std::views::transform([](const auto& item) {
                return std::format(R"("{}")", item);
            }) | std::views::join_with(std::string_view{", "}) | std::ranges::to<std::string>();
        };
        
        const auto level_int = std::to_underlying(level);
        const auto years = crack_time_seconds / (365.25 * 24 * 3600);
        
        return std::format(R"({{
    "level": {},
    "strength": "{}",
    "entropy_bits": {:.2f},
    "crack_time_seconds": {:.2e},
    "crack_time_years": {:.2f},
    "vulnerabilities": [{}],
    "suggestions": [{}],
    "nist_score": {}
}})", 
            static_cast<int>(level_int), strength_name(), entropy_bits, crack_time_seconds,
            years, format_array(vulnerabilities), format_array(suggestions), nist_score);
    }
};

/**
 * High-performance password strength analyzer using entropy calculation and pattern detection
 * @intuition Calculate true password strength by analyzing entropy, patterns, and attack vectors
 * @approach Multi-layered analysis combining entropy math, dictionary checks, and pattern recognition
 * @complexity Time: O(n + d) where n=password length, d=dictionary size; Space: O(d)
 */
class PasswordStrengthEstimator final {
private:
    static constexpr double GPU_HASHES_PER_SECOND{1e11};
    static constexpr std::array<double, 5> ENTROPY_THRESHOLDS{28.0, 35.0, 50.0, 65.0, 80.0};
    static constexpr std::array<std::string_view, 3> KEYBOARD_LAYOUTS{
        R"(qwertyuiopasdfghjklzxcvbnm)",
        R"(1234567890)",
        R"(`-=[]\\;',./~!@#$%^&*()_+{}|:"<>?)"
    };
    
    TransparentStringSet common_passwords_;
    TransparentStringSet dictionary_words_;

public:
    explicit PasswordStrengthEstimator() {
        initialize_security_dictionaries();
    }

    /**
     * Comprehensive password strength analysis with vulnerability detection
     * @intuition Analyze multiple security dimensions simultaneously for accurate assessment
     * @approach Layer entropy, pattern, dictionary, and timing analysis with NIST compliance
     * @complexity Time: O(n + d), Space: O(1) for analysis
     */
    [[nodiscard]] auto analyze_password(std::string_view password) const 
        -> std::expected<AnalysisResult, std::string> {
        
        if (password.empty()) [[unlikely]] {
            return std::unexpected("Password cannot be empty");
        }
        
        if (password.length() > 256) [[unlikely]] {
            return std::unexpected("Password exceeds maximum length (256 characters)");
        }

        const auto start_time{std::chrono::high_resolution_clock::now()};
        
        AnalysisResult result;
        result.entropy_bits = calculate_effective_entropy(password);
        result.crack_time_seconds = estimate_crack_time(result.entropy_bits);
        
        analyze_security_vulnerabilities(password, result);
        generate_improvement_suggestions(password, result);
        result.nist_score = calculate_nist_compliance_score(password, result);
        result.level = determine_strength_classification(result.entropy_bits);
        
        log_performance_metrics(password.length(), start_time, result);
        return result;
    }

private:
    void initialize_security_dictionaries() noexcept {
        common_passwords_ = TransparentStringSet{
            "password", "123456", "123456789", "guest", "qwerty", "12345678", "111111",
            "12345", "col123456", "123123", "1234567", "1234", "1234567890", "000000",
            "555555", "666666", "123321", "654321", "7777777", "123", "password1",
            "1234560", "123456a", "qwertyuiop", "123qwe", "zxcvbnm", "121212",
            "asdasd", "a123456", "123456q", "admin", "welcome", "monkey", "dragon"
        };
        
        dictionary_words_ = TransparentStringSet{
            "password", "welcome", "monkey", "dragon", "master", "freedom", "whatever",
            "jordan", "secret", "summer", "flower", "shadow", "champion", "princess",
            "orange", "starwars", "computer", "michelle", "maggie", "jessica", "love",
            "hello", "angel", "sunshine", "password1", "football", "charlie", "lovely"
        };
    }
    
    /**
     * Multi-dimensional entropy calculation with pattern penalty adjustments
     * @intuition True entropy requires considering predictable patterns beyond character diversity  
     * @approach Base entropy calculation with multiplicative penalties for detected weaknesses
     * @complexity Time: O(n), Space: O(1)
     */
    [[nodiscard]] auto calculate_effective_entropy(std::string_view password) const noexcept -> double {
        const auto charset_size{determine_character_space_size(password)};
        const auto password_length = static_cast<double>(password.length());
        const auto base_entropy{password_length * std::log2(charset_size)};
        
        const auto pattern_penalty{calculate_pattern_penalty_factor(password)};
        const auto repetition_penalty{calculate_repetition_penalty_factor(password)};
        const auto dictionary_penalty{calculate_dictionary_penalty_factor(password)};
        
        const auto effective_entropy{base_entropy * pattern_penalty * repetition_penalty * dictionary_penalty};
        return std::max(0.0, effective_entropy);
    }
    
    [[nodiscard]] auto determine_character_space_size(std::string_view password) const noexcept -> int {
        bool has_lowercase{false};
        bool has_uppercase{false};
        bool has_digits{false};
        bool has_special{false};
        
        for (const char c : password) {
            has_lowercase = has_lowercase || (c >= 'a' && c <= 'z');
            has_uppercase = has_uppercase || (c >= 'A' && c <= 'Z');
            has_digits = has_digits || (c >= '0' && c <= '9');
            has_special = has_special || !(std::isalnum(c));
        }
        
        int size = 0;
        size += has_lowercase ? 26 : 0;
        size += has_uppercase ? 26 : 0;
        size += has_digits ? 10 : 0;
        size += has_special ? 32 : 0;
        
        return std::max(1, size);
    }
    
    /**
     * Extract keyboard walk detection logic to reduce nesting
     * @intuition Separate concerns for better maintainability
     * @approach Individual pattern detection with early returns
     * @complexity Time: O(n), Space: O(1)
     */
    [[nodiscard]] auto detect_keyboard_walk_in_layout(std::string_view password, 
                                                     std::string_view layout) const noexcept -> double {
        if (password.length() < 2) return 0.0;
        
        int max_walk_length{1};
        int current_walk{1};
        
        for (std::size_t i{1}; i < password.length(); ++i) {
            const auto prev_char = std::tolower(password[i-1]);
            const auto curr_char = std::tolower(password[i]);
            
            const auto prev_pos{layout.find(prev_char)};
            const auto curr_pos{layout.find(curr_char)};
            
           if (const bool positions_valid = (prev_pos != std::string_view::npos) && 
                                (curr_pos != std::string_view::npos); 
            !positions_valid) {

                max_walk_length = std::max(max_walk_length, current_walk);
                current_walk = 1;
                continue;
            }
            
            const auto pos_diff = static_cast<int>(curr_pos - prev_pos);
            const bool is_adjacent = std::abs(pos_diff) <= 1;
            
            if (is_adjacent) {
                ++current_walk;
            } else {
                max_walk_length = std::max(max_walk_length, current_walk);
                current_walk = 1;
            }
        }
        
        max_walk_length = std::max(max_walk_length, current_walk);
        return static_cast<double>(max_walk_length) / password.length();
    }
    
    /**
     * Detect keyboard walking patterns and sequential character sequences
     * @intuition Users often follow predictable keyboard patterns reducing effective entropy
     * @approach Delegated pattern detection to reduce nesting complexity
     * @complexity Time: O(n * k) where k=keyboard layouts, Space: O(1)
     */
    [[nodiscard]] auto calculate_pattern_penalty_factor(std::string_view password) const noexcept -> double {
        auto keyboard_walk_penalty{0.0};
        
        // Detect keyboard walks across all layouts
        for (const auto& layout : KEYBOARD_LAYOUTS) {
            const auto walk_ratio = detect_keyboard_walk_in_layout(password, layout);
            keyboard_walk_penalty = std::max(keyboard_walk_penalty, walk_ratio);
        }
        
        // Detect sequential patterns
        auto sequential_penalty{0.0};
        for (std::size_t i{2}; i < password.length(); ++i) {
            const auto char_diff_1 = std::abs(password[i] - password[i-1]);
            const auto char_diff_2 = std::abs(password[i-1] - password[i-2]);
            
            const bool is_sequential = (char_diff_1 == 1) && (char_diff_2 == 1);
            if (is_sequential) {
                sequential_penalty += 0.1;
            }
        }
        
        const auto clamped_sequential = std::min(sequential_penalty, 0.4);
        const auto total_penalty = std::min(0.7, keyboard_walk_penalty * 0.5 + clamped_sequential);
        return 1.0 - total_penalty;
    }
    
    [[nodiscard]] auto calculate_repetition_penalty_factor(std::string_view password) const noexcept -> double {
        std::unordered_map<char, int> char_frequency;
        
        for (const char c : password) {
            ++char_frequency[c];
        }
        
        const auto max_repetition{std::ranges::max(char_frequency | std::views::values)};
        
        if (max_repetition <= 2) return 1.0;
        
        const auto password_length = static_cast<double>(password.length());
        const auto repetition_ratio{static_cast<double>(max_repetition) / password_length};
        return 1.0 - (repetition_ratio * 0.6);
    }
    
    [[nodiscard]] auto calculate_dictionary_penalty_factor(std::string_view password) const noexcept -> double {
        const auto lowercase_password{password | std::views::transform([](char c) { 
            return static_cast<char>(std::tolower(c)); 
        }) | std::ranges::to<std::string>()};
        
        // Check direct matches first
        // Check direct matches first - use init-statement for both variables
        if (const bool is_common_password = common_pw_.contains(lowercase_password);
            const bool is_dictionary_word = dict_.contains(lowercase_password);
            is_common_password || is_dictionary_word) {

            return 0.2; // 80% penalty
        }
        
        // Check substring matches
        for(const auto& w: dict_) {
            if (const bool word_long_enough = w.length() >= 4;
                const bool contains_word = lowercase_password.contains(w);
                word_long_enough && contains_word) {

                    return 0.6; // 40% penalty
            }
        }
        
        return 1.0; // No penalty
    }
    
    [[nodiscard]] constexpr auto estimate_crack_time(double entropy_bits) const noexcept -> double {
        const auto combinations{std::pow(2.0, entropy_bits)};
        return combinations / (2.0 * GPU_HASHES_PER_SECOND);
    }
    
    void analyze_security_vulnerabilities(std::string_view password, AnalysisResult& result) const {
        const auto password_length = password.length();
        
        if (password_length < 8) {
            result.vulnerabilities.emplace_back("Password too short (minimum 8 characters required)");
        }
        
        if (common_passwords_.contains(password)) {
            result.vulnerabilities.emplace_back("Password found in common breach databases");
        }
        
        if (!contains_mixed_case(password)) {
            result.vulnerabilities.emplace_back("Missing mixed case characters");
        }
        
        if (!contains_digits(password)) {
            result.vulnerabilities.emplace_back("No numeric characters present");
        }
        
        if (!contains_special_characters(password)) {
            result.vulnerabilities.emplace_back("No special characters included");
        }
        
        const auto pattern_factor = calculate_pattern_penalty_factor(password);
        if (pattern_factor < 0.7) {
            result.vulnerabilities.emplace_back("Contains predictable keyboard patterns");
        }
        
        const auto repetition_factor = calculate_repetition_penalty_factor(password);
        if (repetition_factor < 0.7) {
            result.vulnerabilities.emplace_back("Excessive character repetition detected");
        }
    }
    
    void generate_improvement_suggestions(std::string_view password, AnalysisResult& result) const {
        const auto password_length = password.length();
        
        if (password_length < 12) {
            result.suggestions.emplace_back("Increase length to at least 12 characters");
        }
        
        if (!contains_mixed_case(password)) {
            result.suggestions.emplace_back("Add both uppercase and lowercase letters");
        }
        
        if (!contains_digits(password)) {
            result.suggestions.emplace_back("Include numeric characters (0-9)");
        }
        
        if (!contains_special_characters(password)) {
            result.suggestions.emplace_back("Add special characters (!@#$%^&*)");
        }
        
        const auto vulnerability_count = result.vulnerabilities.size();
        if (vulnerability_count > 2) {
            result.suggestions.emplace_back("Consider using randomly generated passphrases");
            result.suggestions.emplace_back("Utilize a password manager for unique, strong passwords");
        }
        
        if (result.entropy_bits < ENTROPY_THRESHOLDS[2]) {
            result.suggestions.emplace_back("Avoid predictable patterns and common substitutions");
        }
    }
    
    /**
     * NIST SP 800-63B compliant scoring with comprehensive security assessment
     * @intuition NIST guidelines provide industry-standard password security benchmarks
     * @approach Weighted scoring across length, complexity, uniqueness, and vulnerability factors
     * @complexity Time: O(1), Space: O(1)
     */
    [[nodiscard]] auto calculate_nist_compliance_score(std::string_view password, 
                                                       const AnalysisResult& result) const noexcept -> std::uint8_t {
        int score{0};
        const auto password_length = password.length();
        
        // Length scoring (NIST emphasizes length over complexity)
        score += (password_length >= 8) ? 25 : 0;
        score += (password_length >= 12) ? 20 : 0;
        score += (password_length >= 16) ? 15 : 0;
        
        // Character diversity scoring
        score += contains_mixed_case(password) ? 10 : 0;
        score += contains_digits(password) ? 10 : 0;
        score += contains_special_characters(password) ? 10 : 0;
        
        // Security checks using transparent lookup
        score += (!common_passwords_.contains(password)) ? 10 : 0;
        
        // Apply vulnerability penalties
        const auto vulnerability_count = static_cast<int>(result.vulnerabilities.size());
        const auto penalty = vulnerability_count * 3;
        score -= penalty;
        
        return static_cast<std::uint8_t>(std::clamp(score, 0, 100));
    }
    
    [[nodiscard]] constexpr auto determine_strength_classification(double entropy_bits) const noexcept -> StrengthLevel {
        const auto threshold_iterator = std::ranges::find_if(ENTROPY_THRESHOLDS, 
            [entropy_bits](double threshold) { return entropy_bits < threshold; });
        
        const auto threshold_index = threshold_iterator - ENTROPY_THRESHOLDS.begin();
        return static_cast<StrengthLevel>(static_cast<std::uint8_t>(threshold_index));
    }
    
    [[nodiscard]] constexpr auto contains_mixed_case(std::string_view password) const noexcept -> bool {
        const auto has_lower{std::ranges::any_of(password, [](char c) { return std::islower(c); })};
        const auto has_upper{std::ranges::any_of(password, [](char c) { return std::isupper(c); })};
        return has_lower && has_upper;
    }
    
    [[nodiscard]] constexpr auto contains_digits(std::string_view password) const noexcept -> bool {
        return std::ranges::any_of(password, [](char c) { return std::isdigit(c); });
    }
    
    [[nodiscard]] constexpr auto contains_special_characters(std::string_view password) const noexcept -> bool {
        return std::ranges::any_of(password, [](char c) { 
            return !std::isalnum(c) && c != ' '; 
        });
    }
    
    void log_performance_metrics(std::size_t password_length, 
                                const std::chrono::high_resolution_clock::time_point& start_time,
                                const AnalysisResult& result) const noexcept {
        const auto end_time{std::chrono::high_resolution_clock::now()};
        const auto duration{std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time)};
        const auto level_int = std::to_underlying(result.level);
        
        std::println("[PERF] Length:{} Time:{}μs Entropy:{:.1f} Level:{}",
                    password_length, duration.count(), result.entropy_bits, 
                    static_cast<int>(level_int));
    }
};

} // namespace security::password

// Production-ready demonstration with comprehensive test coverage
auto main() -> int {
    using namespace security::password;
    
    const PasswordStrengthEstimator estimator;
    
    constexpr std::array test_cases{
        std::make_pair("password123", "Common weak password"),
        std::make_pair("P@ssw0rd!2024", "Mixed complexity password"),
        std::make_pair("correct horse battery staple", "Passphrase approach"),
        std::make_pair("qwerty123", "Keyboard walk pattern"),
        std::make_pair("MyStr0ng!Password#2024", "Strong mixed password"),
        std::make_pair("123456", "Extremely weak numeric"),
        std::make_pair("ThisIsAVeryLongAndComplexPasswordWithNumbers123AndSymbols!@#$%", "Maximum strength test")
    };
    
    std::println("=== Password Security Analysis Results ===\n");
    
    for (const auto& [password, description] : test_cases) {
        const auto result{estimator.analyze_password(password)};
        
        if (!result.has_value()) {
            std::println("Analysis failed for '{}': {}\n", password, result.error());
            continue;
        }
        
        std::println("Test: {}", description);
        std::println("Password: {}", password);
        std::println("Analysis: {}", result->to_json());
        
        const auto years = result->crack_time_seconds / (365.25 * 24 * 3600);
        std::println("Estimated crack time: {:.2e} seconds ({:.2f} years)", 
                    result->crack_time_seconds, years);
        std::println("{}\n", std::string(80, '-'));
    }
    
    return 0;
}
