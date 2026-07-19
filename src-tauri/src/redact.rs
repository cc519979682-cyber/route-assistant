use regex::Regex;
use std::sync::OnceLock;

fn secret_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?im)(password|passwd|secret|token|authorization|url)\s*[:=]\s*([^\s,;]+)")
            .expect("redaction regex is static and valid")
    })
}

fn subscription_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"https?://[^\s\"']+"#).expect("URL regex is static and valid"))
}

pub fn redact(input: &str) -> String {
    let step_one = secret_regex().replace_all(input, "$1=[REDACTED]");
    subscription_regex()
        .replace_all(&step_one, "https://[REDACTED]")
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_secrets_and_urls() {
        let value = redact("password=abc secret: xyz url=https://example.com/sub?token=123");
        assert!(!value.contains("abc"));
        assert!(!value.contains("xyz"));
        assert!(!value.contains("example.com"));
    }
}
