#ifndef _CASERV_HTTP_VALIDATION_RULES_H_
#define _CASERV_HTTP_VALIDATION_RULES_H_

#include <format>
#include <regex>
#include <string>
#include <vector>

namespace http {

namespace regex_patterns {
static const char *serial{"^[a-zA-Z0-9_]{1,250}$"};
static const char *thumbprint{"^[a-zA-Z0-9_]{1,250}$"};
} // namespace regex_patterns

struct ValidationRuleResult {
  bool isBroken;
  std::string message;
};

template <typename T> class ValidationRule {
public:
  ValidationRule() = default;
  ValidationRule(const char *name) : _name(name) {}
  virtual ~ValidationRule() = default;
  virtual const ValidationRuleResult Validate(const T &v) = 0;

protected:
  std::string _name;
};

class StringPatternRule : ValidationRule<std::string> {
public:
  StringPatternRule(const char *name, const char *pattern)
      : ValidationRule(name), _pattern(pattern) {}
  ~StringPatternRule();

  const ValidationRuleResult Validate(const std::string &v) override {
    ValidationRuleResult result{.isBroken = false};
    std::regex regex{_pattern};
    if (!std::regex_match(v.c_str(), regex)) {
      result.isBroken = true;
      result.message = std::format(
          "Invalid string format. The string {} did not match the pattern: {}.",
          _name.c_str(), _pattern.c_str());
    }
    return result;
  }

private:
  std::string _pattern;
};

class SerialNumberRule : StringPatternRule {
public:
  SerialNumberRule()
      : StringPatternRule("serialNumber", regex_patterns::serial) {}
};

class ThumbprintRule : StringPatternRule {
public:
  ThumbprintRule()
      : StringPatternRule("thumbprint", regex_patterns::thumbprint) {}
};

} // namespace http

#endif //_CASERV_HTTP_VALIDATION_RULES_H_