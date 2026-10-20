//! Autoservicio de la cuenta: MFA con TOTP y cambio de contrasena (decision 48, §19).
//!
//! Cada operacion asegura una sesion con access token fresco y llama a Cognito con ese
//! token. CSRF lo valida la capa HTTP en los `POST`.

use domain::{DeviceName, Password, TotpCode, TotpSecret};

use crate::ports::{AccountError, AccountManager, AdapterError, Ports};
use crate::{AccountRejection, App, AppError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MfaStatus {
    Enabled,
    Disabled,
}

impl MfaStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::Disabled => "disabled",
        }
    }
}

fn reject(e: AccountError) -> AppError {
    let r = match e {
        AccountError::CodeMismatch => AccountRejection::CodeMismatch,
        AccountError::CodeExpired => AccountRejection::CodeExpired,
        AccountError::NotAuthorized => AccountRejection::NotAuthorized,
        AccountError::InvalidPassword => AccountRejection::InvalidPassword,
        AccountError::MfaSetupInvalid => AccountRejection::MfaSetupInvalid,
        AccountError::TooManyRequests => AccountRejection::TooManyRequests,
        AccountError::Adapter(AdapterError::Transient) => return AppError::UpstreamUnavailable,
        AccountError::Adapter(AdapterError::Permanent) => return AppError::Internal,
    };
    AppError::Account(r)
}

impl<P: Ports> App<P> {
    /// `GET /auth/account/mfa`.
    ///
    /// # Errors
    /// Los de `ensure_fresh_session` y los rechazos de Cognito.
    pub async fn mfa_status(&self, cookie: Option<&str>) -> Result<MfaStatus, AppError> {
        let s = self.ensure_fresh_session(cookie).await?;
        let on = self
            .ports
            .account()
            .mfa_status(&s.tokens.access)
            .await
            .map_err(reject)?;
        Ok(if on {
            MfaStatus::Enabled
        } else {
            MfaStatus::Disabled
        })
    }

    /// `POST /auth/account/mfa/totp/associate`. El secreto sale una sola vez.
    ///
    /// # Errors
    /// Los de `ensure_fresh_session` y los rechazos de Cognito.
    pub async fn associate_totp(&self, cookie: Option<&str>) -> Result<TotpSecret, AppError> {
        let s = self.ensure_fresh_session(cookie).await?;
        self.ports
            .account()
            .associate_totp(&s.tokens.access)
            .await
            .map_err(reject)
    }

    /// `POST /auth/account/mfa/totp/verify`: verifica el codigo y deja el TOTP como
    /// preferido, para que Cognito lo pida en el siguiente login.
    ///
    /// # Errors
    /// Los de `ensure_fresh_session` y los rechazos de Cognito.
    pub async fn verify_totp(
        &self,
        cookie: Option<&str>,
        code: &TotpCode,
        device: Option<&DeviceName>,
    ) -> Result<(), AppError> {
        let s = self.ensure_fresh_session(cookie).await?;
        let account = self.ports.account();
        account
            .verify_totp(&s.tokens.access, code, device)
            .await
            .map_err(reject)?;
        account.set_totp(&s.tokens.access, true).await.map_err(reject)
    }

    /// `POST /auth/account/mfa/preference`.
    ///
    /// # Errors
    /// Los de `ensure_fresh_session` y los rechazos de Cognito.
    pub async fn set_totp(&self, cookie: Option<&str>, enabled: bool) -> Result<(), AppError> {
        let s = self.ensure_fresh_session(cookie).await?;
        self.ports
            .account()
            .set_totp(&s.tokens.access, enabled)
            .await
            .map_err(reject)
    }

    /// `POST /auth/account/change-password`.
    ///
    /// # Errors
    /// Los de `ensure_fresh_session` y los rechazos de Cognito.
    pub async fn change_password(
        &self,
        cookie: Option<&str>,
        previous: &Password,
        proposed: &Password,
    ) -> Result<(), AppError> {
        let s = self.ensure_fresh_session(cookie).await?;
        self.ports
            .account()
            .change_password(&s.tokens.access, previous, proposed)
            .await
            .map_err(reject)
    }
}
