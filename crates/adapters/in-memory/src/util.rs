use std::fmt::Write as _;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll};

use sha2::{Digest, Sha256};

/// Toma el lock ignorando el envenenamiento: un test que entro en panico no debe
/// encadenar fallos en el resto.
pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Cede el turno una vez al ejecutor. Fuerza intercalado entre tareas para que las
/// carreras entre lectura y escritura ocurran de verdad en los tests.
#[derive(Debug, Default)]
pub(crate) struct YieldNow(bool);

impl Future for YieldNow {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.0 {
            Poll::Ready(())
        } else {
            self.0 = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

pub(crate) fn digest(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // Escribir en un String no falla.
        let _ = write!(out, "{b:02x}");
    }
    out
}
