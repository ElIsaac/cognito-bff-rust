use application::ports::AdapterError;
use aws_sdk_dynamodb::config::http::HttpResponse;
use aws_sdk_dynamodb::error::{ProvideErrorMetadata, SdkError};

const SERVER_ERROR_MIN_STATUS: u16 = 500;

/// Codigos de `DynamoDB` que indican presion de capacidad: reintentables.
const THROTTLING_CODES: &[&str] = &[
    "ProvisionedThroughputExceededException",
    "ThrottlingException",
    "RequestLimitExceeded",
    "ThrottledException",
    "InternalServerError",
    "ServiceUnavailable",
];

/// Traduce un error del SDK. Registra solo la operacion y el codigo, nunca valores.
pub(crate) fn classify<E: ProvideErrorMetadata>(
    op: &'static str,
    e: &SdkError<E, HttpResponse>,
) -> AdapterError {
    let code = e.code();
    let transient = match e {
        SdkError::TimeoutError(_) | SdkError::DispatchFailure(_) => true,
        SdkError::ServiceError(se) => {
            se.raw().status().as_u16() >= SERVER_ERROR_MIN_STATUS
                || code.is_some_and(|c| THROTTLING_CODES.contains(&c))
        }
        SdkError::ResponseError(re) => re.raw().status().as_u16() >= SERVER_ERROR_MIN_STATUS,
        _ => false,
    };
    tracing::warn!(op, code = code.unwrap_or("none"), transient, "fallo de DynamoDB");
    if transient {
        AdapterError::Transient
    } else {
        AdapterError::Permanent
    }
}

/// `true` si el servicio rechazo la escritura por la `ConditionExpression`.
pub(crate) fn is_conditional_failure<E: ProvideErrorMetadata>(e: &SdkError<E, HttpResponse>) -> bool {
    e.code() == Some("ConditionalCheckFailedException")
}
