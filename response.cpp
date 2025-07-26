/******************************************************************************
 * High-performance C++23 password-strength estimator (single-file version)
 * @intuition Combine true entropy math with pattern & dictionary penalties
 * @approach Layered analysis → entropy → pattern detection → dictionary check
 * @complexity
 *   Time O(n + d) (n = password length, d = dictionary size)
 *   Space O(d)
 ******************************************************************************/
#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <expected>
#include <format>
#include <functional>
#include <print>
#include <ranges>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace security::password {

/*--------------------------------------------------------*
 |                small utilities / aliases               |
 *--------------------------------------------------------*/
enum class StrengthLevel : std::uint8_t {
    VERY_WEAK, WEAK, FAIR, GOOD, STRONG, VERY_STRONG
};

struct TransparentStringHasher {
    using is_transparent = void;

    auto operator()(std::string_view sv) const noexcept -> std::size_t {
        return std::hash<std::string_view>{}(sv);
    }
    auto operator()(const std::string& s) const noexcept -> std::size_t {
        return std::hash<std::string>{}(s);
    }
    auto operator()(const char* s) const noexcept -> std::size_t {
        return std::hash<std::string_view>{}(s);
    }
};
using TransparentSet =
    std::unordered_set<std::string, TransparentStringHasher, std::equal_to<>>;

/*--------------------------------------------------------*
 |                    result structure                    |
 *--------------------------------------------------------*/
struct AnalysisResult final {
    StrengthLevel level{StrengthLevel::VERY_WEAK};
    double        entropy_bits{0.0};
    double        crack_time_seconds{0.0};
    std::vector<std::string> vulnerabilities;
    std::vector<std::string> suggestions;
    std::uint8_t nist_score{0};

    [[nodiscard]] constexpr auto strength_name() const noexcept -> std::string_view {
        constexpr std::array names{
            "Very Weak","Weak","Fair","Good","Strong","Very Strong"};
        return names[static_cast<std::size_t>(level)];
    }

    [[nodiscard]] auto to_json() const -> std::string {
        auto join_strings = [](const auto& vec) {
            return vec
                 | std::views::transform([](const std::string& s) {
                       return std::format(R"("{}")", s);
                   })
                 | std::views::join_with(std::string_view{", "})
                 | std::ranges::to<std::string>();
        };

        const auto years = crack_time_seconds / (365.25 * 24 * 3600);

        return std::format(R"({{"level": {},
    "strength": "{}",
    "entropy_bits": {:.2f},
    "crack_time_seconds": {:.2e},
    "crack_time_years": {:.2f},
    "vulnerabilities": [{}],
    "suggestions": [{}],
    "nist_score": {}
}})",
            static_cast<int>(std::to_underlying(level)),
            strength_name(),
            entropy_bits,
            crack_time_seconds,
            years,
            join_strings(vulnerabilities),
            join_strings(suggestions),
            nist_score);
    }
};

/*--------------------------------------------------------*
 |               PasswordStrengthEstimator                |
 *--------------------------------------------------------*/
class PasswordStrengthEstimator final {
private:
    /*--------- constants ---------*/
    static constexpr double GPU_HASHES_PER_SECOND{1e11};
    static constexpr std::array<double,5> ENTROPY_THRESH{28,35,50,65,80};
    static constexpr std::array<std::string_view,3> KEYBOARD_LAYOUTS{
        R"(qwertyuiopasdfghjklzxcvbnm)",
        R"(1234567890)",
        R"(`-=[]\;',./~!@#$%^&*()_+{}|:"<>?)"};

    /*--------- dictionaries ---------*/
    TransparentSet common_pw_;
    TransparentSet dict_;

public:
    explicit PasswordStrengthEstimator() { init_dictionaries(); }

    /**
     * Analyse password and return complete security report
     */
    [[nodiscard]]
    auto analyze_password(std::string_view pw) const
        -> std::expected<AnalysisResult,std::string>
    {
        if (pw.empty())               return std::unexpected("Password is empty");
        if (pw.length() > 256)        return std::unexpected("Password too long");

        const auto start = std::chrono::high_resolution_clock::now();

        AnalysisResult r;
        r.entropy_bits        = effective_entropy(pw);
        r.crack_time_seconds  = crack_time(r.entropy_bits);
        detect_vulnerabilities(pw, r);
        suggest_improvements(pw, r);
        r.nist_score          = nist_score(pw, r);
        r.level               = classify(r.entropy_bits);

        log_metrics(pw.length(), start, r);
        return r;
    }

private:
    /*--------- dictionary initialisation ---------*/
    void init_dictionaries() {
        common_pw_ = {
            "password","123456","123456789","guest","qwerty","12345678","111111",
            "12345","123123","1234567","1234","1234567890","000000","password1",
            "admin","welcome","monkey","dragon","lovely","football","iloveyou"
        };
        dict_ = {
            "welcome","monkey","dragon","master","freedom","whatever","jordan",
            "secret","summer","flower","shadow","princess","computer","sunshine",
            "hello","angel","charlie","lovely","football"
        };
    }

    /*--------- entropy & helpers ---------*/
    [[nodiscard]] static auto char_space(std::string_view pw) noexcept -> int {
        bool lo=false, up=false, di=false, sp=false;
        for(char c: pw){
            lo |= std::islower(c);
            up |= std::isupper(c);
            di |= std::isdigit(c);
            sp |= !std::isalnum(c);
        }
        return (lo?26:0)+(up?26:0)+(di?10:0)+(sp?32:0);
    }

    [[nodiscard]] auto keyboard_walk_ratio(std::string_view pw,
                                           std::string_view layout) const noexcept -> double
    {
        if (pw.length()<2) return 0.0;
        int max_walk=1, walk=1;
        for(std::size_t i=1;i<pw.length();++i){
            const auto ppos = layout.find(std::tolower(pw[i-1]));
            const auto cpos = layout.find(std::tolower(pw[i]));
            if (const bool valid = (ppos!=std::string_view::npos)&&(cpos!=std::string_view::npos);
                !valid)
            {
                max_walk = std::max(max_walk, walk); walk=1; continue;
            }
            if (std::abs(static_cast<int>(cpos-ppos))<=1) ++walk;
            else { max_walk = std::max(max_walk, walk); walk=1; }
        }
        max_walk = std::max(max_walk, walk);
        return static_cast<double>(max_walk)/pw.length();
    }

    [[nodiscard]] auto pattern_penalty(std::string_view pw) const noexcept -> double {
        double kb_pen=0.0;
        for(auto layout: KEYBOARD_LAYOUTS)
            kb_pen = std::max(kb_pen, keyboard_walk_ratio(pw, layout));

        double seq_pen=0.0;
        for(std::size_t i=2;i<pw.length();++i)
            if (std::abs(pw[i]-pw[i-1])==1 && std::abs(pw[i-1]-pw[i-2])==1)
                seq_pen += 0.1;
        seq_pen = std::min(seq_pen, 0.4);

        return 1.0 - std::min(0.7, kb_pen*0.5 + seq_pen);
    }

    [[nodiscard]] static auto repetition_penalty(std::string_view pw) noexcept -> double {
        std::unordered_map<char,int> freq;
        for(char c: pw) ++freq[c];
        const int max_rep = std::ranges::max(freq|std::views::values);
        if (max_rep<=2) return 1.0;
        return 1.0 - (static_cast<double>(max_rep)/pw.length())*0.6;
    }

    [[nodiscard]] auto dictionary_penalty(std::string_view pw) const noexcept -> double {
        const std::string lower = pw
            | std::views::transform([](char c){return char(std::tolower(c));})
            | std::ranges::to<std::string>();

        if (const bool is_dict = dict_.contains(lower);
            common_pw_.contains(lower) || is_dict)
            return 0.2;

        for(const auto& w: dict_)
            if (w.length()>=4 && lower.contains(w)) return 0.6;

        return 1.0;
    }

    [[nodiscard]] auto effective_entropy(std::string_view pw) const noexcept -> double {
        const double base = pw.length()*std::log2(char_space(pw));
        return std::max(0.0, base * pattern_penalty(pw)
                               * repetition_penalty(pw)
                               * dictionary_penalty(pw));
    }

    [[nodiscard]] static constexpr auto crack_time(double bits) noexcept -> double {
        const double combos = std::pow(2.0, bits);
        return combos / (2.0*GPU_HASHES_PER_SECOND);
    }

    /*--------- vulnerability & suggestions ---------*/
    void detect_vulnerabilities(std::string_view pw, AnalysisResult& r) const {
        if (pw.length()<8)            r.vulnerabilities.emplace_back("Too short (<8)");
        if (common_pw_.contains(pw))  r.vulnerabilities.emplace_back("Common password");
        if (!mixed_case(pw))          r.vulnerabilities.emplace_back("Missing mixed case");
        if (!has_digit(pw))           r.vulnerabilities.emplace_back("No digits");
        if (!has_special(pw))         r.vulnerabilities.emplace_back("No special chars");
        if (pattern_penalty(pw)<0.7)  r.vulnerabilities.emplace_back("Keyboard/sequence pattern");
        if (repetition_penalty(pw)<0.7) r.vulnerabilities.emplace_back("High repetition");
    }

    void suggest_improvements(std::string_view pw, AnalysisResult& r) const {
        if (pw.length()<12)  r.suggestions.emplace_back("Use ≥12 characters");
        if (!mixed_case(pw)) r.suggestions.emplace_back("Add upper & lower case");
        if (!has_digit(pw))  r.suggestions.emplace_back("Add digits");
        if (!has_special(pw))r.suggestions.emplace_back("Add special characters");
        if (r.vulnerabilities.size()>2)
            r.suggestions.emplace_back("Consider a random pass-phrase or password manager");
        if (r.entropy_bits<ENTROPY_THRESH[2])
            r.suggestions.emplace_back("Avoid predictable patterns/substitutions");
    }

    /*--------- NIST scoring & classification ---------*/
    [[nodiscard]] static auto nist_score(std::string_view pw,
                                         const AnalysisResult& r) noexcept -> std::uint8_t
    {
        int s=0; const auto len=pw.length();
        s += (len>=8)?25:0;  s += (len>=12)?20:0; s += (len>=16)?15:0;
        s += mixed_case(pw)?10:0; s += has_digit(pw)?10:0; s += has_special(pw)?10:0;
        s += (!common_pw_.contains(pw))?10:0;
        s -= static_cast<int>(r.vulnerabilities.size())*3;
        return static_cast<std::uint8_t>(std::clamp(s,0,100));
    }

    [[nodiscard]] static constexpr auto classify(double bits) noexcept -> StrengthLevel {
        const auto it = std::ranges::find_if(ENTROPY_THRESH,
                       [bits](double t){return bits<t;});
        return static_cast<StrengthLevel>(it-ENTROPY_THRESH.begin());
    }

    /*--------- helpers ---------*/
    static constexpr bool mixed_case(std::string_view pw) noexcept {
        return std::ranges::any_of(pw,[](char c){return std::islower(c);}) &&
               std::ranges::any_of(pw,[](char c){return std::isupper(c);});
    }
    static constexpr bool has_digit(std::string_view pw) noexcept {
        return std::ranges::any_of(pw,[](char c){return std::isdigit(c);});
    }
    static constexpr bool has_special(std::string_view pw) noexcept {
        return std::ranges::any_of(pw,[](char c){return !std::isalnum(c)&&c!=' ';});
    }

    /*--------- logging ---------*/
    static void log_metrics(std::size_t len,
                            std::chrono::high_resolution_clock::time_point start,
                            const AnalysisResult& r) noexcept
    {
        const auto dur = std::chrono::duration_cast<std::chrono::microseconds>(
                             std::chrono::high_resolution_clock::now()-start).count();
        std::println("[METRIC] len={} time={}µs entropy={:.1f} level={}",
                     len, dur, r.entropy_bits,
                     static_cast<int>(std::to_underlying(r.level)));
    }
};

/*--------------------------------------------------------*
 |                       demo main                        |
 *--------------------------------------------------------*/
auto main() -> int {
    using namespace security::password;

    const PasswordStrengthEstimator est;

    constexpr std::array tests{
        std::pair{"password123","common weak"},
        std::pair{"P@ssw0rd!2024","mixed"},
        std::pair{"correct horse battery staple","pass-phrase"},
        std::pair{"qwerty123","keyboard pattern"},
        std::pair{"MyStr0ng!Password#2024","strong"},
        std::pair{"123456","numeric weak"},
        std::pair{"ThisIsAVeryLongAndComplexPasswordWithNumbers123AndSymbols!@#$%","max strength"}
    };

    for(auto [pw,desc]:tests){
        auto res = est.analyze_password(pw);
        if(!res){
            std::println("❌  {} → {}", desc, res.error());
            continue;
        }
        std::println("\n🔍  {}  [{}]", desc, pw);
        std::println("{}", res->to_json());
    }
    return 0;
}
