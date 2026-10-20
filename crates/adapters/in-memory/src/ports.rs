use application::ports::Ports;

use crate::account::FakeAccount;
use crate::clock::TestClock;
use crate::idp::FakeIdp;
use crate::rng::TestRng;
use crate::sessions::MemSessions;
use crate::stores::{MemPending, MemTickets};
use crate::upstream::FakeUpstream;

/// Todos los fakes agrupados. Los accesores (`idp()`, `account()`, `sessions()`, `pending()`, `tickets()`,
/// `upstream()`, `clock()`, `rng()`) devuelven los tipos concretos para poder hacer asserts.
#[derive(Debug)]
pub struct MemPorts {
    idp: FakeIdp,
    account: FakeAccount,
    sessions: MemSessions,
    pending: MemPending,
    tickets: MemTickets,
    upstream: FakeUpstream,
    clock: TestClock,
    rng: TestRng,
}

impl Default for MemPorts {
    fn default() -> Self {
        Self::new()
    }
}

impl MemPorts {
    /// Crear dentro del runtime de tokio del test: el reloj toma el instante actual.
    pub fn new() -> Self {
        let clock = TestClock::new();
        Self {
            idp: FakeIdp::new(clock),
            account: FakeAccount::new(),
            sessions: MemSessions::new(),
            pending: MemPending::new(),
            tickets: MemTickets::new(),
            upstream: FakeUpstream::new(),
            clock,
            rng: TestRng::default(),
        }
    }
}

/// Accesores inherentes: no hace falta importar `Ports` para usarlos en los tests.
impl MemPorts {
    pub fn idp(&self) -> &FakeIdp {
        &self.idp
    }

    pub fn account(&self) -> &FakeAccount {
        &self.account
    }

    pub fn sessions(&self) -> &MemSessions {
        &self.sessions
    }

    pub fn pending(&self) -> &MemPending {
        &self.pending
    }

    pub fn tickets(&self) -> &MemTickets {
        &self.tickets
    }

    pub fn upstream(&self) -> &FakeUpstream {
        &self.upstream
    }

    pub fn clock(&self) -> &TestClock {
        &self.clock
    }

    pub fn rng(&self) -> &TestRng {
        &self.rng
    }
}

impl Ports for MemPorts {
    type Idp = FakeIdp;
    type Account = FakeAccount;
    type Sessions = MemSessions;
    type Pending = MemPending;
    type Tickets = MemTickets;
    type Upstream = FakeUpstream;
    type Clock = TestClock;
    type Rng = TestRng;

    fn idp(&self) -> &FakeIdp {
        &self.idp
    }

    fn account(&self) -> &FakeAccount {
        &self.account
    }

    fn sessions(&self) -> &MemSessions {
        &self.sessions
    }

    fn pending(&self) -> &MemPending {
        &self.pending
    }

    fn tickets(&self) -> &MemTickets {
        &self.tickets
    }

    fn upstream(&self) -> &FakeUpstream {
        &self.upstream
    }

    fn clock(&self) -> &TestClock {
        &self.clock
    }

    fn rng(&self) -> &TestRng {
        &self.rng
    }
}
