use anyhow::{Result, anyhow};
use fernet::Fernet;
use log::warn;

const ENCRYPTION_KEY_B64: &str = "OPwdflh9vDTVrt5ulyGE6UmHvSMVf0Vc3jxrqAMak_Q=";

fn get_cipher() -> Result<Fernet> {
    Fernet::new(ENCRYPTION_KEY_B64).ok_or_else(|| anyhow!("无效的加密密钥"))
}

pub fn encrypt_password(password: &str) -> Result<String> {
    Ok(get_cipher()?.encrypt(password.as_bytes()))
}

pub fn decrypt_password(encrypted: &str) -> String {
    match get_cipher() {
        Ok(cipher) => match cipher.decrypt(encrypted) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
            Err(_) => {
                warn!("无法解密密码，可能它是明文或无效的。");
                encrypted.to_string()
            }
        },
        Err(_) => encrypted.to_string(),
    }
}
