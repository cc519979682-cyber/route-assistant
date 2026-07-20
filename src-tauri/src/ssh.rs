use crate::error::{AppError, AppResult};
use crate::models::{AuthKind, CommandOutput, RouterProfileInput};
use russh::client;
use russh::keys::{HashAlg, PrivateKeyWithHashAlg, PublicKey, load_secret_key};
use russh::{ChannelMsg, Disconnect};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Clone)]
struct SshHandler {
    fingerprint: Arc<Mutex<Option<String>>>,
}

impl client::Handler for SshHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        let value = server_public_key.fingerprint(HashAlg::Sha256).to_string();
        if let Ok(mut fingerprint) = self.fingerprint.lock() {
            *fingerprint = Some(value);
        }
        Ok(true)
    }
}

pub struct SshSession {
    handle: client::Handle<SshHandler>,
}

impl SshSession {
    pub async fn probe_host_key(input: &RouterProfileInput) -> AppResult<String> {
        validate_connection_input(input)?;
        let captured = Arc::new(Mutex::new(None));
        let handler = SshHandler {
            fingerprint: captured.clone(),
        };
        let config = Arc::new(client::Config {
            inactivity_timeout: Some(Duration::from_secs(12)),
            keepalive_interval: Some(Duration::from_secs(8)),
            keepalive_max: 2,
            ..Default::default()
        });
        let handle = tokio::time::timeout(
            Duration::from_secs(15),
            client::connect(config, (input.host.as_str(), input.port), handler),
        )
        .await
        .map_err(|_| AppError::Ssh("连接超时，请检查 IP、端口和防火墙".into()))?
        .map_err(|error| AppError::Ssh(error.to_string()))?;

        let _ = handle
            .disconnect(
                Disconnect::ByApplication,
                "host key probe complete",
                "zh-CN",
            )
            .await;
        captured
            .lock()
            .ok()
            .and_then(|value| value.clone())
            .ok_or_else(|| AppError::Ssh("未能读取 SSH 主机指纹".into()))
    }

    pub async fn connect(
        input: &RouterProfileInput,
        expected_fingerprint: &str,
    ) -> AppResult<Self> {
        validate_connection_input(input)?;
        let captured = Arc::new(Mutex::new(None));
        let handler = SshHandler {
            fingerprint: captured.clone(),
        };
        let config = Arc::new(client::Config {
            inactivity_timeout: Some(Duration::from_secs(20)),
            keepalive_interval: Some(Duration::from_secs(8)),
            keepalive_max: 3,
            ..Default::default()
        });
        let mut handle = tokio::time::timeout(
            Duration::from_secs(20),
            client::connect(config, (input.host.as_str(), input.port), handler),
        )
        .await
        .map_err(|_| AppError::Ssh("连接超时，请检查 IP、端口和防火墙".into()))?
        .map_err(|error| AppError::Ssh(error.to_string()))?;

        let fingerprint = captured
            .lock()
            .ok()
            .and_then(|value| value.clone())
            .ok_or_else(|| AppError::Ssh("未能读取 SSH 主机指纹".into()))?;
        if fingerprint != expected_fingerprint {
            let _ = handle
                .disconnect(Disconnect::ByApplication, "host key mismatch", "zh-CN")
                .await;
            return Err(AppError::HostKeyChanged(format!(
                "保存的是 {expected_fingerprint}，当前为 {fingerprint}"
            )));
        }

        let authenticated = match input.auth_kind {
            AuthKind::Password => {
                let password = input
                    .password
                    .as_deref()
                    .ok_or_else(|| AppError::Credential("没有提供 SSH 密码".into()))?;
                handle
                    .authenticate_password(&input.username, password)
                    .await
                    .map_err(|error| AppError::Ssh(error.to_string()))?
                    .success()
            }
            AuthKind::PrivateKey => {
                let path = input
                    .private_key_path
                    .as_deref()
                    .ok_or_else(|| AppError::Credential("没有选择 SSH 私钥".into()))?;
                let key = load_secret_key(path, input.private_key_passphrase.as_deref())
                    .map_err(|error| AppError::Credential(error.to_string()))?;
                let algorithm = handle
                    .best_supported_rsa_hash()
                    .await
                    .map_err(|error| AppError::Ssh(error.to_string()))?
                    .flatten();
                handle
                    .authenticate_publickey(
                        &input.username,
                        PrivateKeyWithHashAlg::new(Arc::new(key), algorithm),
                    )
                    .await
                    .map_err(|error| AppError::Ssh(error.to_string()))?
                    .success()
            }
        };
        if !authenticated {
            return Err(AppError::Ssh("身份验证失败，请检查用户名和凭据".into()));
        }

        Ok(Self { handle })
    }

    pub async fn run(&self, command: &str) -> AppResult<CommandOutput> {
        let mut channel = self
            .handle
            .channel_open_session()
            .await
            .map_err(|error| AppError::Ssh(error.to_string()))?;
        channel
            .exec(true, command)
            .await
            .map_err(|error| AppError::Ssh(error.to_string()))?;

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut status = None;
        while let Some(message) = channel.wait().await {
            match message {
                ChannelMsg::Data { data } => {
                    if stdout.len() + data.len() <= 4 * 1024 * 1024 {
                        stdout.extend_from_slice(&data);
                    }
                }
                ChannelMsg::ExtendedData { data, .. } => {
                    if stderr.len() + data.len() <= 1024 * 1024 {
                        stderr.extend_from_slice(&data);
                    }
                }
                ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
                _ => {}
            }
        }
        Ok(CommandOutput {
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            exit_status: status.unwrap_or(255),
        })
    }

    pub async fn run_checked(&self, command: &str) -> AppResult<String> {
        let output = self.run(command).await?;
        if output.exit_status != 0 {
            return Err(AppError::Ssh(if output.stderr.trim().is_empty() {
                format!("远程命令返回状态 {}", output.exit_status)
            } else {
                output.stderr.trim().to_owned()
            }));
        }
        Ok(output.stdout)
    }

    pub async fn write_file(&self, path: &str, content: &[u8], mode: u32) -> AppResult<()> {
        // OpenClash routers often ship Ruby but no coreutils `base64`.
        // Transfer file contents as hex and decode with Ruby.
        let encoded = hex::encode(content);
        let temporary = format!("{path}.route-assistant.tmp");
        let command = format!(
            concat!(
                "umask 077; set -e; ",
                "tmp={tmp}; ",
                "printf %s {payload} | ruby -e 'print STDIN.read.strip.scan(/../).map{{|h| h.to_i(16).chr}}.join' > \"$tmp\"; ",
                "actual=$(wc -c < \"$tmp\" | tr -d ' \n'); ",
                "test \"$actual\" = \"{len}\"; ",
                "chmod {mode:o} \"$tmp\"; ",
                "mv -f \"$tmp\" {path}; ",
                "test -f {path}"
            ),
            tmp = shell_quote(&temporary),
            payload = shell_quote(&encoded),
            len = content.len(),
            mode = mode,
            path = shell_quote(path),
        );
        self.run_checked(&command).await.map(|_| ())
    }

    pub async fn api_get(
        &self,
        port: u16,
        secret: Option<&str>,
        path: &str,
    ) -> AppResult<serde_json::Value> {
        if !path.starts_with('/') || path.contains(' ') {
            return Err(AppError::Validation("Mihomo API 路径无效".into()));
        }
        if secret.is_some_and(|value| value.contains(['\r', '\n'])) {
            return Err(AppError::Validation("Mihomo API 密钥格式无效".into()));
        }
        let response = tokio::time::timeout(Duration::from_secs(10), async {
            let mut channel = self
                .handle
                .channel_open_direct_tcpip("127.0.0.1", u32::from(port), "127.0.0.1", 0)
                .await
                .map_err(|error| AppError::Ssh(format!("无法建立 Mihomo SSH 隧道：{error}")))?;
            let authorization = secret
                            .filter(|value| !value.is_empty())
                            .map(|value| format!("Authorization: Bearer {value}\r\n"))
                            .unwrap_or_default();
                        let request = format!(
                            "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAccept: application/json\r\n{authorization}Connection: close\r\n\r\n"
                        );
            channel
                .data(request.as_bytes())
                .await
                .map_err(|error| AppError::Ssh(error.to_string()))?;
            channel.eof().await.map_err(|error| AppError::Ssh(error.to_string()))?;
            let mut bytes = Vec::new();
            while let Some(message) = channel.wait().await {
                match message {
                    ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. } => {
                        if bytes.len() + data.len() > 8 * 1024 * 1024 {
                            return Err(AppError::Ssh("Mihomo API 响应超过安全上限".into()));
                        }
                        bytes.extend_from_slice(&data);
                    }
                    _ => {}
                }
            }
            parse_http_response(&bytes)
        })
        .await
        .map_err(|_| AppError::Ssh("Mihomo API SSH 隧道请求超时".into()))??;
        serde_json::from_slice(&response)
            .map_err(|error| AppError::Ssh(format!("Mihomo API 返回无效数据：{error}")))
    }

    pub async fn disconnect(self) {
        let _ = self
            .handle
            .disconnect(Disconnect::ByApplication, "done", "zh-CN")
            .await;
    }
}

fn parse_http_response(response: &[u8]) -> AppResult<Vec<u8>> {
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| AppError::Ssh("Mihomo API 返回了不完整的 HTTP 响应".into()))?;
    let headers = std::str::from_utf8(&response[..header_end])
        .map_err(|_| AppError::Ssh("Mihomo API HTTP 头无效".into()))?;
    let status = headers.lines().next().unwrap_or_default();
    if !status
        .split_whitespace()
        .nth(1)
        .is_some_and(|code| code == "200")
    {
        return Err(AppError::Ssh(format!("Mihomo API 请求失败：{status}")));
    }
    let body = &response[(header_end + 4)..];
    let chunked = headers.lines().skip(1).any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("transfer-encoding")
                && value
                    .split(',')
                    .any(|item| item.trim().eq_ignore_ascii_case("chunked"))
        })
    });
    if !chunked {
        return Ok(body.to_vec());
    }
    decode_chunked_body(body)
}

fn decode_chunked_body(mut input: &[u8]) -> AppResult<Vec<u8>> {
    let mut output = Vec::new();
    loop {
        let line_end = input
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| AppError::Ssh("Mihomo API 分块响应无效".into()))?;
        let size_text = std::str::from_utf8(&input[..line_end])
            .map_err(|_| AppError::Ssh("Mihomo API 分块长度无效".into()))?;
        let size =
            usize::from_str_radix(size_text.split(';').next().unwrap_or_default().trim(), 16)
                .map_err(|_| AppError::Ssh("Mihomo API 分块长度无效".into()))?;
        input = &input[(line_end + 2)..];
        if size == 0 {
            return Ok(output);
        }
        if input.len() < size + 2 || &input[size..(size + 2)] != b"\r\n" {
            return Err(AppError::Ssh("Mihomo API 分块响应被截断".into()));
        }
        output.extend_from_slice(&input[..size]);
        input = &input[(size + 2)..];
    }
}

pub fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn validate_connection_input(input: &RouterProfileInput) -> AppResult<()> {
    if input.host.trim().is_empty() || input.host.contains(char::is_whitespace) {
        return Err(AppError::Validation("软路由地址无效".into()));
    }
    if input.port == 0 {
        return Err(AppError::Validation("SSH 端口无效".into()));
    }
    if input.username.trim().is_empty() {
        return Err(AppError::Validation("SSH 用户名不能为空".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_quotes_single_quotes() {
        assert_eq!(shell_quote("a'b"), "'a'\\''b'");
    }

    #[test]
    fn parses_plain_and_chunked_http_responses() {
        let plain = b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n{\"a\":1}";
        assert_eq!(parse_http_response(plain).unwrap(), b"{\"a\":1}");

        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"a\"\r\n3\r\n:1}\r\n0\r\n\r\n";
        assert_eq!(parse_http_response(chunked).unwrap(), b"{\"a\":1}");
    }
}
