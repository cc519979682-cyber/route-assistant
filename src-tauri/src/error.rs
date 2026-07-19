use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("输入无效：{0}")]
    Validation(String),
    #[error("SSH 连接失败：{0}")]
    Ssh(String),
    #[error("软路由身份已变化，已阻止连接：{0}")]
    HostKeyChanged(String),
    #[error("需要先确认 SSH 主机指纹：{0}")]
    HostKeyUntrusted(String),
    #[error("凭据读取失败：{0}")]
    Credential(String),
    #[error("不支持当前代理插件或版本：{0}")]
    Unsupported(String),
    #[error("检测到规则冲突：{0}")]
    Conflict(String),
    #[error("安全验证失败，已尝试回滚：{0}")]
    Verification(String),
    #[error("本地存储失败：{0}")]
    Storage(String),
    #[error("操作失败：{0}")]
    Other(String),
}

impl Serialize for AppError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

pub type AppResult<T> = Result<T, AppError>;

impl From<anyhow::Error> for AppError {
    fn from(value: anyhow::Error) -> Self {
        Self::Other(value.to_string())
    }
}

