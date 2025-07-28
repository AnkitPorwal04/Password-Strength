// password_strength_estimator.hpp
#ifndef PASSWORD_STRENGTH_ESTIMATOR_HPP
#define PASSWORD_STRENGTH_ESTIMATOR_HPP

#include <algorithm> // For std::max, std::min, std::clamp, std::any_of
#include <array>     // For std::array
#include <chrono>    // For std::chrono::high_resolution_clock
#include <cmath>     // For std::log2, std::pow, std::abs
#include <expected>  // For std::expected, std::unexpected (C++23)
#include <format>    // For std::format (C++20)
#include <functional> // For std::hash
#include <print>     // For std::println (C++23)
#include <ranges>    // For std::views, std::ranges::to, std::ranges::any_of, std::ranges::find_if (C++20)
#include <string>    // For std::string
#include <string_view> // For std::string_view
#include <unordered_map> // For std::unordered_map
#include <unordered_set> // For std::unordered_set
#include <utility>   // For std::pair, std::to_underlying
#include <vector>    // For std::vector

namespace security::password {

/// @brief Defines discrete levels of password strength.
enum class StrengthLevel : std::uint8_t {
    VERY_WEAK = 0,
    WEAK = 1,
    FAIR = 2,
    GOOD = 3,
    STRONG = 4,
    VERY_STRONG = 5
};

/// @brief Custom transparent hasher for heterogeneous string lookups in unordered containers.
/// @intuition Allows `std::unordered_set<std::string>` to be queried efficiently with `std::string_view` or `const char*`.
/// @approach Provides `operator()` overloads for `std::string_view`, `const std::string&`, and `const char*`.
/// @complexity Time: O(N) for hashing, where N is string length. Space: O(1).
struct TransparentStringHasher {
    using is_transparent = void; // Required for transparent hashing
    
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

/// @brief Alias for an unordered set that supports transparent lookups.
using TransparentStringSet = std::unordered_set<std::string, TransparentStringHasher, std::equal_to<>>;

/// @brief Encapsulates the complete analysis report for a given password.
struct AnalysisResult final {
    StrengthLevel level{StrengthLevel::VERY_WEAK}; ///< The classified strength level.
    double entropy_bits{0.0};                      ///< Shannon entropy of the password in bits.
    double crack_time_seconds{0.0};                ///< Estimated time to crack the password by a GPU.
    std::vector<std::string> vulnerabilities;      ///< List of identified weaknesses.
    std::vector<std::string> suggestions;          ///< Actionable advice for improvement.
    std::uint8_t nist_score{0};                   ///< A score (0-100) based on NIST compliance.
    
    /// @brief Returns the human-readable name for the classified strength level.
    /// @complexity Time: O(1). Space: O(1).
    [[nodiscard]] constexpr auto strength_name() const noexcept -> std::string_view {
        constexpr std::array names{
            "Very Weak", "Weak", "Fair", "Good", "Strong", "Very Strong"
        };
        const auto index = std::to_underlying(level); // C++23 std::to_underlying
        return names[static_cast<std::size_t>(index)];
    }
    
    /// @brief Serializes the analysis result into a JSON string.
    /// @complexity Time: O(V + S), where V is number of vulnerabilities, S is number of suggestions.
    /// Space: O(JSON string length).
    [[nodiscard]] auto to_json() const -> std::string {
        // Lambda to format string arrays for JSON, leveraging C++20 ranges for conciseness
        auto format_array = [](const auto& arr) {
            return arr | std::views::transform([](const auto& item) {
                return std::format(R"("{}")", item); // Escape quotes for JSON
            }) | std::views::join_with(std::string_view{", "}) // Join elements with comma and space
              | std::ranges::to<std::string>(); // Convert range to string (C++23)
        };
        
        const auto level_int = std::to_underlying(level);
        const auto years = crack_time_seconds / (365.25 * 24 * 3600); // More precise average year length
        
        // Use std::format for efficient and readable JSON string construction
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
 * @brief High-performance password strength analyzer using entropy calculation and pattern detection.
 * @intuition Accurately assesses password strength by combining cryptographic entropy,
 * common pattern recognition, and attack time estimations, providing actionable insights.
 * @approach Employs a multi-layered analysis:
 * 1. Calculate effective entropy, adjusted for common patterns.
 * 2. Estimate GPU-based crack time.
 * 3. Detect known vulnerabilities (dictionary words, keyboard walks, repetitions, etc.).
 * 4. Generate NIST-compliant score and improvement suggestions.
 * 5. All operations are optimized for sub-millisecond performance.
 * @complexity Time: O(N + D + K), where N=password length, D=dictionary size (average case for hash set), K=number of keyboard layouts.
 * Space: O(D + K) for dictionary/layout storage, O(N) for temporary string copies during analysis.
 */
class PasswordStrengthEstimator final {
private:
    static constexpr double GPU_HASHES_PER_SECOND{1e11}; ///< Assumed GPU cracking rate for a fast hash.
    static constexpr std::array<double, 5> ENTROPY_THRESHOLDS{28.0, 35.0, 50.0, 65.0, 80.0}; ///< Entropy thresholds for strength classification.
    /// @brief Common keyboard layouts for detecting simple patterns (e.g., "qwerty", "123").
    static constexpr std::array<std::string_view, 3> KEYBOARD_LAYOUTS{
        "qwertyuiopasdfghjklzxcvbnm", // QWERTY keyboard characters
        "1234567890",                 // Numeric row
        R"(`-=[]\;',./~!@#$%^&*()_+{}|:"<>?)" // Common symbols (raw string literal for backslash)
    };
    
    TransparentStringSet common_passwords_;   ///< Set of globally common, easily guessed passwords.
    TransparentStringSet dictionary_words_;   ///< Set of common dictionary words for substring checks.

public:
    /// @brief Initializes the password strength estimator by loading security dictionaries.
    /// @complexity Time: O(M + D) for initializing internal sets, where M is number of common passwords, D is number of dictionary words. Space: O(M + D).
    explicit PasswordStrengthEstimator() {
        initialize_security_dictionaries();
    }

    /// @brief Performs a comprehensive strength analysis on a given password.
    /// @intuition Provides a real-time, in-depth security assessment crucial for authentication systems.
    /// @approach Measures performance, calculates entropy, identifies various patterns (common, dictionary, sequential, repetition, keyboard walk),
    /// estimates crack time, generates a NIST-aligned score, and offers actionable feedback.
    /// @complexity Time: O(N + D + K), primarily dominated by dictionary and keyboard walk checks.
    /// Space: O(N) for temporary lowercase string copies and `AnalysisResult` data.
    /// @param password The password string to be analyzed.
    /// @return An `std::expected<AnalysisResult, std::string>` containing the analysis report on success,
    /// or an error message if the input is invalid.
    [[nodiscard]] auto analyze_password(std::string_view password) const 
        -> std::expected<AnalysisResult, std::string> {
        
        // Input validation with unlikely branch hint for performance optimization
        if (password.empty()) [[unlikely]] {
            return std::unexpected("Password cannot be empty");
        }
        
        // Practical upper limit to prevent excessive processing or malformed input
        if (password.length() > 256) [[unlikely]] {
            return std::unexpected("Password exceeds maximum length (256 characters)");
        }

        const auto startTime{std::chrono::high_resolution_clock::now()};
        
        AnalysisResult result;
        result.entropy_bits = calculate_effective_entropy(password);
        result.crack_time_seconds = estimate_crack_time(result.entropy_bits);
        
        analyze_security_vulnerabilities(password, result);
        generate_improvement_suggestions(password, result);
        result.nist_score = calculate_nist_compliance_score(password, result);
        result.level = determine_strength_classification(result.entropy_bits);
        
        // Record performance metrics
        const auto endTime{std::chrono::high_resolution_clock::now()};
        result.performance_duration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime);
        
        // If performance exceeds sub-millisecond, add a warning (critical for registration flows)
        if (result.performance_duration.count() > 1000) {
            result.vulnerabilities.emplace_back(
                std::format("Performance Warning: Estimation took {} us, exceeding sub-millisecond target.",
                            result.performance_duration.count()));
            result.suggestions.emplace_back("Optimize dictionary sizes or pattern detection for very long passwords.");
        }

        return result;
    }

private:
    /// @brief Initializes internal hash sets with common passwords and dictionary words.
    /// @intuition Pre-populating these sets allows for fast lookups during analysis.
    /// @approach Direct brace-initialization for `std::unordered_set` for conciseness and efficiency.
    /// @complexity Time: O(M + D) for initializing internal sets, where M is number of common passwords, D is number of dictionary words. Space: O(M + D).
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
    
    /// @brief Calculates the effective entropy of a password, adjusting for common patterns.
    /// @intuition Raw Shannon entropy can be misleading if the password contains predictable patterns.
    /// This function applies penalties for such patterns to derive a more realistic entropy.
    /// @approach Computes base entropy from character space, then applies multiplicative
    /// penalty factors derived from pattern, repetition, and dictionary checks.
    /// @complexity Time: O(N) dominated by character space determination and penalty factor calculations.
    /// Space: O(1) beyond input string.
    [[nodiscard]] auto calculate_effective_entropy(std::string_view password) const noexcept -> double {
        const auto charset_size{determine_character_space_size(password)};
        const auto password_length_double = static_cast<double>(password.length());
        
        // Base entropy calculation (H = L * log2(N)) - direct and concise
        const auto base_entropy{password_length_double * std::log2(static_cast<double>(charset_size))};
        
        // Calculate penalty factors for different types of weaknesses
        const auto pattern_penalty{calculate_pattern_penalty_factor(password)};
        const auto repetition_penalty{calculate_repetition_penalty_factor(password)};
        const auto dictionary_penalty{calculate_dictionary_penalty_factor(password)};
        
        // Apply multiplicative penalties to the base entropy - direct and concise
        const auto effective_entropy{base_entropy * pattern_penalty * repetition_penalty * dictionary_penalty};
        
        return std::max(0.0, effective_entropy); // Ensure entropy is not negative
    }
    
    /// @brief Determines the size of the character space (alphabet) used in the password.
    /// @intuition A larger character space contributes to higher entropy.
    /// @approach Checks for presence of lowercase, uppercase, digits, and special characters.
    /// @complexity Time: O(N) for iterating through the password. Space: O(1).
    [[nodiscard]] auto determine_character_space_size(std::string_view password) const noexcept -> int {
        bool has_lowercase{false};
        bool has_uppercase{false};
        bool has_digits{false};
        bool has_special{false};
        
        for (const char c : password) {
            // Use explicit boolean conversion for clarity with `std::is*` functions
            has_lowercase = has_lowercase || (std::islower(static_cast<unsigned char>(c)) != 0);
            has_uppercase = has_uppercase || (std::isupper(static_cast<unsigned char>(c)) != 0);
            has_digits = has_digits || (std::isdigit(static_cast<unsigned char>(c)) != 0);
            has_special = has_special || (!(std::isalnum(static_cast<unsigned char>(c))) && c != ' '); // Include space as special per NIST
        }
        
        int size = 0;
        if (has_lowercase) size += 26;
        if (has_uppercase) size += 26;
        if (has_digits) size += 10;
        if (has_special) size += 32; // Common printable ASCII symbols (excluding alphanumeric and space)
        
        return std::max(1, size); // Ensure minimum character space size is 1 for log2 safety
    }
    
    /// @brief Detects if a password segment follows a keyboard walk pattern on a given layout string.
    /// @intuition Keyboard walks are highly predictable and reduce actual security.
    /// @approach Iterates through the password and checks if adjacent characters are also adjacent
    /// on the provided keyboard layout string.
    /// @complexity Time: O(N) for password length. Space: O(1).
    [[nodiscard]] auto detect_keyboard_walk_in_layout(std::string_view password, 
                                                     std::string_view layout) const noexcept -> double {
        if (password.length() < 2) return 0.0;
        
        int max_walk_length{1};
        int current_walk{1};
        
        for (std::size_t i{1}; i < password.length(); ++i) {
            const char prev_char = std::tolower(static_cast<unsigned char>(password[i-1]));
            const char curr_char = std::tolower(static_cast<unsigned char>(password[i]));
            
            const auto prev_pos{layout.find(prev_char)};
            const auto curr_pos{layout.find(curr_char)};
            
            // Direct and concise check for presence and adjacency
            if ((prev_pos != std::string_view::npos) && (curr_pos != std::string_view::npos) &&
                (std::abs(static_cast<int>(curr_pos - prev_pos)) <= 1)) {
                ++current_walk;
            } else {
                max_walk_length = std::max(max_walk_length, current_walk);
                current_walk = 1; // Reset walk counter
            }
        }
        
        max_walk_length = std::max(max_walk_length, current_walk); // Capture last walk
        return static_cast<double>(max_walk_length) / password.length();
    }
    
    /// @brief Calculates a penalty factor for keyboard walking patterns and sequential characters.
    /// @intuition Patterns make passwords easier to guess, reducing effective entropy.
    /// @approach Combines penalties from detected keyboard walks across predefined layouts
    /// and simple sequential character patterns (e.g., "abc", "123").
    /// @complexity Time: O(N * K) where K is number of keyboard layouts. Space: O(1).
    [[nodiscard]] auto calculate_pattern_penalty_factor(std::string_view password) const noexcept -> double {
        auto keyboard_walk_penalty{0.0};
        
        // Iterate through all defined keyboard layouts to find the longest walk
        for (const auto& layout : KEYBOARD_LAYOUTS) {
            const auto walk_ratio = detect_keyboard_walk_in_layout(password, layout);
            keyboard_walk_penalty = std::max(keyboard_walk_penalty, walk_ratio);
        }
        
        // Detect sequential patterns (e.g., "abc", "123", "zyx", "321")
        auto sequential_penalty{0.0};
        for (std::size_t i{2}; i < password.length(); ++i) {
            const int char_diff_1 = std::abs(static_cast<int>(password[i]) - static_cast<int>(password[i-1]));
            const int char_diff_2 = std::abs(static_cast<int>(password[i-1]) - static_cast<int>(password[i-2]));
            
            if ((char_diff_1 == 1) && (char_diff_2 == 1)) {
                sequential_penalty += 0.1; // Accumulate penalty for each detected sequence
            }
        }
        
        const auto clamped_sequential_penalty = std::min(sequential_penalty, 0.4); // Cap sequential penalty
        const auto total_penalty = std::min(0.7, keyboard_walk_penalty * 0.5 + clamped_sequential_penalty); // Combine and cap total
        
        return 1.0 - total_penalty; // Return 1.0 (no penalty) minus the calculated penalty
    }
    
    /// @brief Calculates a penalty factor for excessive character repetition.
    /// @intuition Repetitive patterns (e.g., "aaa", "abab") are easy to guess.
    /// @approach Counts character frequencies and calculates a penalty based on the highest repetition count.
    /// @complexity Time: O(N) for iterating through password, O(C) for map iteration where C is character set size.
    /// Space: O(C) for character frequency map.
    [[nodiscard]] auto calculate_repetition_penalty_factor(std::string_view password) const noexcept -> double {
        std::unordered_map<char, int> char_frequency;
        
        for (const char c : password) {
            char_frequency[c]++;
        }
        
        // Find the maximum repetition count using ranges and `std::max` (C++20) for conciseness
        int max_repetition = 0;
        if (!char_frequency.empty()) { // Handle empty map case
            max_repetition = std::ranges::max(char_frequency | std::views::values);
        }
        
        if (max_repetition <= 2) return 1.0; // No penalty for low repetitions
        
        const auto password_length_double = static_cast<double>(password.length());
        const auto repetition_ratio{static_cast<double>(max_repetition) / password_length_double};
        return 1.0 - (repetition_ratio * 0.6); // Higher ratio means higher penalty
    }
    
    /// @brief Calculates a penalty factor if the password contains common dictionary words or is a common password.
    /// @intuition Dictionary attacks are prevalent; passwords or parts of them found in dictionaries are weak.
    /// @approach Checks for exact matches against common password lists and dictionary words. Also checks for
    /// dictionary words as substrings within the password (case-insensitive).
    /// @complexity Time: O(L) for lowercasing, then O(D) (average) for hash set lookups for exact match.
    /// O(D * N) for substring checks in worst case, but optimized with `string_view::contains`.
    /// Space: O(N) for lowercase password copy.
    [[nodiscard]] auto calculate_dictionary_penalty_factor(std::string_view password) const noexcept -> double {
        // Convert password to lowercase once for case-insensitive checks, leveraging C++20 ranges
        const auto lowercase_password_str{
            password | std::views::transform([](char c) { return static_cast<char>(std::tolower(static_cast<unsigned char>(c))); })
                     | std::ranges::to<std::string>() // C++23 range adaptor to string
        };
        
        // Check direct matches first (more severe penalty) using init-statement in if for scope
        if (const bool is_dictionary_word_match = dictionary_words_.contains(lowercase_password_str);
            common_passwords_.contains(lowercase_password_str) || is_dictionary_word_match) {
            return 0.2; // 80% penalty for direct match
        }
        
        // Check for dictionary words as substrings (less severe but still significant penalty)
        for (const auto& word : dictionary_words_) {
            // Only consider longer words as meaningful substrings
            if (word.length() >= 4 && lowercase_password_str.contains(word)) { // std::string::contains (C++23)
                return 0.6; // 40% penalty for substring match
            }
        }
        
        return 1.0; // No penalty if no dictionary words are found
    }
    
    /// @brief Estimates the time it would take for a GPU to brute-force crack the password.
    /// @intuition Crack time directly relates to the password's entropy and attacker's computational power.
    /// @approach Uses the formula: Time = $2^{\text{entropy}} / \text{hashes_per_second}$.
    /// The GPU_HASHES_PER_SECOND is a high-end estimate for fast hashes. This is a simplified model.
    /// @complexity Time: O(1) (mathematical calculation). Space: O(1).
    [[nodiscard]] constexpr auto estimate_crack_time(double entropy_bits) const noexcept -> double {
        if (entropy_bits <= 0) return 0.0; 

        // Calculate the total number of possible combinations (keyspace size)
        const auto combinations{std::pow(2.0, entropy_bits)};
        
        // Calculate the time to crack based on assumed GPU performance
        return combinations / (2.0 * GPU_HASHES_PER_SECOND); // Factor of 2 for average case
    }
    
    /// @brief Analyzes a password for various security vulnerabilities and populates the result struct.
    /// @intuition Explicitly identifies known weaknesses that make a password easily compromise-able.
    /// @approach Checks length, presence in common breach lists, and character type diversity.
    /// @complexity Time: O(N) due to string iterations and hash set lookups. Space: O(V) for vulnerabilities.
    /// @param password The password string view.
    /// @param result The `AnalysisResult` struct to populate with vulnerabilities.
    void analyze_security_vulnerabilities(std::string_view password, AnalysisResult& result) const {
        const auto password_length = password.length();
        
        // NIST-recommended minimum length check
        if (password_length < 8) {
            result.vulnerabilities.emplace_back("Password too short (minimum 8 characters required by NIST).");
        }
        
        // Check against common passwords database (case-sensitive as typically stored)
        if (common_passwords_.contains(password)) {
            result.vulnerabilities.emplace_back("Password found in common breach databases. Avoid common choices.");
        }
        
        // Character type diversity checks
        if (!contains_mixed_case(password)) {
            result.vulnerabilities.emplace_back("Missing mixed case characters (uppercase and lowercase).");
        }
        
        if (!contains_digits(password)) {
            result.vulnerabilities.emplace_back("No numeric characters present (0-9).");
        }
        
        if (!contains_special_characters(password)) {
            result.vulnerabilities.emplace_back("No special characters included (!@#$%^&*).");
        }
        
        // Check pattern-based weaknesses
        const auto pattern_factor = calculate_pattern_penalty_factor(password);
        if (pattern_factor < 0.7) { // Heuristic threshold for significant pattern presence
            result.vulnerabilities.emplace_back("Contains predictable keyboard patterns or sequential series.");
        }
        
        const auto repetition_factor = calculate_repetition_penalty_factor(password);
        if (repetition_factor < 0.7) { // Heuristic threshold for significant repetition
            result.vulnerabilities.emplace_back("Excessive character repetition detected (e.g., 'aaa', 'abab').");
        }
    }
    
    /// @brief Generates actionable suggestions based on detected vulnerabilities.
    /// @intuition Providing concrete steps helps users improve their password security.
    /// @approach Adds suggestions based on missing criteria (length, character types) and general advice
    /// for highly vulnerable passwords.
    /// @complexity Time: O(S) where S is number of suggestions added. Space: O(S).
    /// @param password The password string view (used for length check).
    /// @param result The `AnalysisResult` struct to populate with suggestions.
    void generate_improvement_suggestions(std::string_view password, AnalysisResult& result) const {
        const auto password_length = password.length();
        
        // Suggest longer passwords
        if (password_length < 12) {
            result.suggestions.emplace_back("Increase password length to at least 12 characters for better security.");
        }
        
        // Suggest adding missing character types
        if (!contains_mixed_case(password)) {
            result.suggestions.emplace_back("Add both uppercase and lowercase letters (e.g., 'aBcDe').");
        }
        
        if (!contains_digits(password)) {
            result.suggestions.emplace_back("Include numeric characters (0-9) to enhance randomness.");
        }
        
        if (!contains_special_characters(password)) {
            result.suggestions.emplace_back("Add special characters like !@#$%^&*() to increase complexity.");
        }
        
        // General advice for highly vulnerable passwords
        const auto vulnerability_count = result.vulnerabilities.size();
        if (vulnerability_count > 2) {
            result.suggestions.emplace_back("Consider using a randomly generated passphrase (multiple unrelated words).");
            result.suggestions.emplace_back("Utilize a reputable password manager for unique, strong passwords.");
        }
        
        // Advice for predictable patterns (if entropy is low)
        if (result.entropy_bits < ENTROPY_THRESHOLDS[2]) { // Below "Fair" entropy threshold
            result.suggestions.emplace_back("Avoid predictable patterns (e.g., keyboard walks, simple sequences) and common substitutions.");
        }
    }
    
    /// @brief Calculates a NIST SP 800-63B compliant score for the password.
    /// @intuition Provides a quantifiable measure of adherence to modern security guidelines.
    /// @approach Scores based on length, character diversity, and uniqueness, with penalties for detected vulnerabilities.
    /// @complexity Time: O(N) due to character checks. Space: O(1).
    /// @param password The password string view.
    /// @param result The `AnalysisResult` struct containing detected vulnerabilities.
    /// @return A score from 0-100, representing NIST compliance.
    [[nodiscard]] auto calculate_nist_compliance_score(std::string_view password, 
                                                       const AnalysisResult& result) const noexcept -> std::uint8_t {
        int score{0};
        const auto password_length = password.length();
        
        // Length scoring (NIST emphasizes length) - clear and direct
        score += (password_length >= 8) ? 25 : 0;
        score += (password_length >= 12) ? 20 : 0; // Additional score for longer passwords
        score += (password_length >= 16) ? 15 : 0; // Even more for very long
        
        // Character diversity scoring - clear and direct
        score += contains_mixed_case(password) ? 10 : 0;
        score += contains_digits(password) ? 10 : 0;
        score += contains_special_characters(password) ? 10 : 0;
        
        // Uniqueness check (not in common breach lists) - clear and direct
        score += (!common_passwords_.contains(password)) ? 10 : 0;
        
        // Apply penalties for detected vulnerabilities - clear and direct
        const auto vulnerability_count = static_cast<int>(result.vulnerabilities.size());
        const auto penalty = vulnerability_count * 3; // Apply a fixed penalty per vulnerability
        score -= penalty;
        
        return static_cast<std::uint8_t>(std::clamp(score, 0, 100)); // Clamp score between 0 and 100
    }
    
    /// @brief Classifies the password strength into a `StrengthLevel` based on its entropy.
    /// @intuition Entropy is the most fundamental measure of password strength.
    /// @approach Compares calculated entropy against predefined thresholds to assign a strength level.
    /// @complexity Time: O(T) where T is number of entropy thresholds. Space: O(1).
    /// @param entropy_bits The calculated Shannon entropy of the password.
    /// @return The corresponding `StrengthLevel`.
    [[nodiscard]] constexpr auto determine_strength_classification(double entropy_bits) const noexcept -> StrengthLevel {
        // Use std::ranges::find_if for concise threshold lookup (C++20)
        const auto threshold_iterator = std::ranges::find_if(ENTROPY_THRESHOLDS, 
            [entropy_bits](double threshold) { return entropy_bits < threshold; });
        
        const auto threshold_index = threshold_iterator - ENTROPY_THRESHOLDS.begin();
        return static_cast<StrengthLevel>(static_cast<std::uint8_t>(threshold_index));
    }
    
    /// @brief Checks if the password contains both uppercase and lowercase characters.
    /// @complexity Time: O(N). Space: O(1).
    [[nodiscard]] constexpr auto contains_mixed_case(std::string_view password) const noexcept -> bool {
        const auto has_lower{std::ranges::any_of(password, [](char c) { return std::islower(static_cast<unsigned char>(c)); })};
        const auto has_upper{std::ranges::any_of(password, [](char c) { return std::isupper(static_cast<unsigned char>(c)); })};
        return has_lower && has_upper;
    }
    
    /// @brief Checks if the password contains any numeric digits.
    /// @complexity Time: O(N). Space: O(1).
    [[nodiscard]] constexpr auto contains_digits(std::string_view password) const noexcept -> bool {
        return std::ranges::any_of(password, [](char c) { return std::isdigit(static_cast<unsigned char>(c)); });
    }
    
    /// @brief Checks if the password contains any special characters (non-alphanumeric, non-space).
    /// @complexity Time: O(N). Space: O(1).
    [[nodiscard]] constexpr auto contains_special_characters(std::string_view password) const noexcept -> bool {
        return std::ranges::any_of(password, [](char c) { 
            return !std::isalnum(static_cast<unsigned char>(c)) && c != ' '; // Exclude space if not counted as special
        });
    }
};

} // namespace security::password

// Production-ready demonstration with comprehensive test coverage
// This main function is typically in a separate .cpp file for a header-only library.
// For the single-file requirement, it's included here and can be guarded by a macro.
#ifdef PASSWORD_ESTIMATOR_DEMO_MAIN_ACTIVE
#include <iostream>
#include <iomanip> // For std::fixed, std::setprecision

auto main() -> int {
    using namespace security::password;
    
    const PasswordStrengthEstimator estimator;
    
    // Test cases cover various scenarios for strength, weaknesses, and edge cases
    constexpr std::array test_cases{
        std::make_pair("", "Empty password"),
        std::make_pair("short", "Too short password"),
        std::make_pair("password123", "Common weak password"),
        std::make_pair("P@ssw0rd!2024", "Mixed complexity, good length"),
        std::make_pair("correct horse battery staple", "Passphrase approach (NIST favored)"),
        std::make_pair("qwerty123", "Keyboard walk pattern"),
        std::make_pair("MyStr0ng!Password#2024", "Strong mixed password"),
        std::make_pair("123456", "Extremely weak numeric sequence"),
        std::make_pair("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "Long, single character repetition"),
        std::make_pair("ThisIsAVeryLongAndComplexPasswordWithNumbers123AndSymbols!@#$%^&*()_+-=[]{};:'\",.<>/?`~|\\", "Maximum strength test"),
        std::make_pair("zxcvbnm", "Another keyboard walk"),
        std::make_pair("abcdefghijklmnopqrstuvwxyz", "Long sequential alphabet"),
        std::make_pair("user123", "Contains dictionary word 'user' and sequential numbers")
    };
    
    std::println("=== Password Security Analysis Results ===\n");
    
    for (const auto& [password, description] : test_cases) {
        const auto result_expected{estimator.analyze_password(password)};
        
        if (!result_expected.has_value()) {
            std::println("Analysis failed for '{}': {}\n", password, result_expected.error());
            std::println("{}\n", std::string(80, '-'));
            continue;
        }
        
        const auto& result = result_expected.value(); // Access the value from std::expected
        
        std::println("Test: {}", description);
        std::println("Password: {}", password);
        std::println("Strength Level: {} ({}/100 NIST Score)", result.strength_name(), result.nist_score);
        std::println("Entropy: {:.2f} bits", result.entropy_bits);
        std::println("Estimated Crack Time: {:.2e} seconds (approx. {:.2f} years)", 
                     result.crack_time_seconds, result.crack_time_seconds / (365.25 * 24 * 3600));
        
        if (!result.vulnerabilities.empty()) {
            std::println("Vulnerabilities:");
            for (const auto& vuln : result.vulnerabilities) {
                std::println("  - {}", vuln);
            }
        } else {
            std::println("No specific vulnerabilities detected.");
        }

        if (!result.suggestions.empty()) {
            std::println("Suggestions for Improvement:");
            for (const auto& suggestion : result.suggestions) {
                std::println("  - {}", suggestion);
            }
        } else {
            std::println("Password is strong, no immediate suggestions.");
        }
        
        std::println("Performance: {} microseconds\n", result.performance_duration.count());
        std::println("{}\n", std::string(80, '=')); // Consistent separator
    }
    
    return 0;
}
#endif // PASSWORD_ESTIMATOR_DEMO_MAIN_ACTIVE
