use crate::error::{AppError, AppResult};
use crate::models::MatchScope;
use url::Url;

pub fn normalize_domain(input: &str, scope: &MatchScope) -> AppResult<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(AppError::Validation("域名不能为空".into()));
    }

    let candidate = if trimmed.contains("://") {
        trimmed.to_owned()
    } else {
        format!("https://{trimmed}")
    };
    let parsed = Url::parse(&candidate)
        .map_err(|_| AppError::Validation("无法识别域名或网址".into()))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| AppError::Validation("网址中没有有效域名".into()))?
        .trim_end_matches('.')
        .to_lowercase();

    if host.parse::<std::net::IpAddr>().is_ok() {
        return Err(AppError::Validation("首版只支持域名，不支持 IP 地址规则".into()));
    }
    if host.contains('*') || host.contains('_') {
        return Err(AppError::Validation("请输入普通域名，不需要通配符".into()));
    }

    let ascii = idna::domain_to_ascii(&host)
        .map_err(|_| AppError::Validation("国际化域名格式无效".into()))?;
    let labels: Vec<&str> = ascii.split('.').collect();
    if labels.len() < 2 || labels.iter().any(|label| label.is_empty() || label.len() > 63) {
        return Err(AppError::Validation("请输入完整域名，例如 www.baidu.com".into()));
    }

    if matches!(scope, MatchScope::Suffix) {
        Ok(ascii.trim_start_matches("www.").to_owned())
    } else {
        Ok(ascii)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_url_path_and_port() {
        assert_eq!(
            normalize_domain("https://WWW.Baidu.com:443/search?q=x", &MatchScope::Exact).unwrap(),
            "www.baidu.com"
        );
    }

    #[test]
    fn suffix_scope_strips_common_www_label() {
        assert_eq!(
            normalize_domain("www.baidu.com", &MatchScope::Suffix).unwrap(),
            "baidu.com"
        );
    }

    #[test]
    fn converts_international_domain() {
        assert_eq!(
            normalize_domain("例子.测试", &MatchScope::Exact).unwrap(),
            "xn--fsqu00a.xn--0zwm56d"
        );
    }

    #[test]
    fn rejects_ip_and_wildcard() {
        assert!(normalize_domain("192.168.1.1", &MatchScope::Exact).is_err());
        assert!(normalize_domain("*.example.com", &MatchScope::Suffix).is_err());
    }
}

