use std::sync::Mutex;

use application::ports::{AccountError, AccountManager};
use domain::{AccessToken, DeviceName, Password, TotpCode, TotpSecret};

use crate::util::lock;

/// Secreto TOTP que entrega `associate_totp`.
pub const FAKE_TOTP_SECRET: &str = "JBSWY3DPEHPK3PXP";
/// Unico codigo que `verify_totp` acepta.
pub const FAKE_TOTP_CODE: &str = "123456";
/// Contrasena inicial del usuario.
pub const FAKE_PASSWORD: &str = "Inicial-123";

#[derive(Debug)]
struct State {
    totp_enabled: bool,
    associated: bool,
    verified: bool,
    password: String,
    fail_next: Option<AccountError>,
    /// `(operacion, access token)` de cada llamada, para comprobar que usa el de la sesion.
    calls: Vec<(&'static str, String)>,
}

/// Cuenta de Cognito de mentira con las reglas basicas: verificar exige un TOTP asociado,
/// activarlo exige uno verificado y cambiar la contrasena exige la actual.
#[derive(Debug)]
pub struct FakeAccount {
    state: Mutex<State>,
}

impl Default for FakeAccount {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeAccount {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(State {
                totp_enabled: false,
                associated: false,
                verified: false,
                password: FAKE_PASSWORD.to_owned(),
                fail_next: None,
                calls: Vec::new(),
            }),
        }
    }

    /// La siguiente llamada falla con `e`.
    pub fn fail_next(&self, e: AccountError) {
        lock(&self.state).fail_next = Some(e);
    }

    pub fn totp_enabled(&self) -> bool {
        lock(&self.state).totp_enabled
    }

    pub fn password(&self) -> String {
        lock(&self.state).password.clone()
    }

    pub fn calls(&self) -> Vec<(&'static str, String)> {
        lock(&self.state).calls.clone()
    }

    fn enter(
        &self,
        op: &'static str,
        access: &AccessToken,
    ) -> Result<std::sync::MutexGuard<'_, State>, AccountError> {
        let mut s = lock(&self.state);
        s.calls.push((op, access.expose_secret().to_owned()));
        match s.fail_next.take() {
            Some(e) => Err(e),
            None => Ok(s),
        }
    }
}

impl AccountManager for FakeAccount {
    async fn mfa_status(&self, access: &AccessToken) -> Result<bool, AccountError> {
        Ok(self.enter("mfa_status", access)?.totp_enabled)
    }

    async fn associate_totp(&self, access: &AccessToken) -> Result<TotpSecret, AccountError> {
        let mut s = self.enter("associate_totp", access)?;
        s.associated = true;
        s.verified = false;
        TotpSecret::new(FAKE_TOTP_SECRET.to_owned()).map_err(|_| AccountError::MfaSetupInvalid)
    }

    async fn verify_totp(
        &self,
        access: &AccessToken,
        code: &TotpCode,
        _device: Option<&DeviceName>,
    ) -> Result<(), AccountError> {
        let mut s = self.enter("verify_totp", access)?;
        if !s.associated {
            return Err(AccountError::MfaSetupInvalid);
        }
        if code.expose_secret() != FAKE_TOTP_CODE {
            return Err(AccountError::CodeMismatch);
        }
        s.verified = true;
        Ok(())
    }

    async fn set_totp(&self, access: &AccessToken, enabled: bool) -> Result<(), AccountError> {
        let mut s = self.enter("set_totp", access)?;
        if enabled && !s.verified {
            return Err(AccountError::MfaSetupInvalid);
        }
        s.totp_enabled = enabled;
        Ok(())
    }

    async fn change_password(
        &self,
        access: &AccessToken,
        previous: &Password,
        proposed: &Password,
    ) -> Result<(), AccountError> {
        let mut s = self.enter("change_password", access)?;
        if previous.expose_secret() != s.password {
            return Err(AccountError::NotAuthorized);
        }
        if proposed.expose_secret().len() < 8 {
            return Err(AccountError::InvalidPassword);
        }
        proposed.expose_secret().clone_into(&mut s.password);
        Ok(())
    }
}
