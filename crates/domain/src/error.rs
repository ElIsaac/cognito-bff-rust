/// Violacion de una invariante del dominio.
///
/// Los mensajes describen la regla incumplida, nunca el valor recibido: un valor rechazado
/// puede ser un token o un identificador de sesion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DomainError {
    #[error("identificador aleatorio con formato invalido")]
    InvalidRandomId,
    #[error("code_verifier con formato invalido")]
    InvalidCodeVerifier,
    #[error("returnTo invalido")]
    InvalidReturnTo,
    #[error("email invalido")]
    InvalidEmail,
    #[error("nombre de grupo invalido")]
    InvalidGroupName,
    #[error("subject invalido")]
    InvalidSubject,
    #[error("token vacio o demasiado largo")]
    InvalidToken,
    #[error("configuracion de politica de sesion invalida: {0}")]
    InvalidPolicy(&'static str),
}
