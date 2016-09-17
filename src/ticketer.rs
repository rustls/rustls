
use {rand, suites};
use suites::SupportedCipherSuite;
use cipher::MessageCipher;
use session::{SessionRandoms, SessionSecrets};
use msgs::enums::{ProtocolVersion, ContentType};
use msgs::message::{Message, MessagePayload};
use server::ProducesTickets;

use std::io::Write;
use time;
use std::mem;
use std::sync::Mutex;

/// A thing that can produce and unwrap tickets reusing the
/// standard record layer.
///
/// ## Design
/// RFC5077 recommends a ticket format based on an adhoc
/// generic composition of AES128-CBC and HMAC-SHA256.
///
/// That seems like a shame, because every TLS stack already has
/// code to do encryption and decryption of arbitrary messages:
/// the record layer.  The following is the glue needed to bring
/// the two systems together:
///
/// * To build one, you need a secret key of any length.
///   This is treated as the premaster secret, with zeroes as
///   server and client randoms.  This gives us a master secret
///   which has the same entropy as the original key, and the
///   right length.  It is standardly and deterministically
///   generated from the pre-master secret.
///
/// * To create a ticket, we start with a plaintext (which is an
///   encoding of a `ServerSessionValue` but opaque at this level).
///   We choose a 32-byte random which takes the place of the
///   server_random, and then derive the key block using it,
///   with zeroes as the client random, and the aforementioned
///   master secret.
///   Next we encapsulate the plaintext in a TLSv1.2 ApplicationData
///   message, with sequence number zero.  This is encrypted.
///   The ticket is the fragment of this message with the server
///   random prefixed to it.
///
/// * To decrypt a ticket, take the first 32 bytes and construct
///   a record layer as before.  Put the rest of the ticket into
///   an ApplicationData message, and decrypt with the sequence
///   number zero.
///
/// Note that it would be simpler and faster to generate tickets
/// in a single record layer instantiation, with a sequence number
/// prefixed.  However, publishing a sequence number would be a
/// privacy leak.
///
pub struct StandardCiphersuiteTicketer {
  secrets: SessionSecrets,
  suite: &'static SupportedCipherSuite,
  lifetime: u32
}

impl StandardCiphersuiteTicketer {
  /// Make a ticketer using the given ciphersuite `suite`,
  /// `key` (which should be high-entropy and of any length),
  /// and `lifetime_seconds` which is a ticket's lifetime in seconds.
  pub fn new_custom(suite: &'static SupportedCipherSuite, key: &[u8],
                    lifetime_seconds: u32) -> StandardCiphersuiteTicketer {
    StandardCiphersuiteTicketer {
      secrets: SessionSecrets::new(&SessionRandoms::zeroes(),
                                   suite.get_hash(),
                                   key),
      suite: suite,
      lifetime: lifetime_seconds
    }
  }

  /// Make a ticketer with recommended configuration and a random key.
  pub fn new() -> StandardCiphersuiteTicketer {
    let mut key = [0u8; 32];
    rand::fill_random(&mut key);
    StandardCiphersuiteTicketer::new_custom(
      &suites::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
      &key,
      60 * 60 * 12)
  }
}

impl ProducesTickets for StandardCiphersuiteTicketer {
  fn enabled(&self) -> bool { true }
  fn get_lifetime(&self) -> u32 { self.lifetime }

  /// Encrypt `message` and return the ciphertext.
  fn encrypt(&self, message: &[u8]) -> Option<Vec<u8>> {
    let sec = SessionSecrets::new_resume(&SessionRandoms::for_server(),
                                         self.suite.get_hash(),
                                         &self.secrets.get_master_secret());
    let cipher = MessageCipher::new(self.suite, &sec);

    let message = Message {
      typ: ContentType::ApplicationData,
      version: ProtocolVersion::TLSv1_2,
      payload: MessagePayload::opaque(message.to_vec())
    };
    
    let result = match cipher.encrypt(&message, 0) {
      Ok(m) => m,
      Err(_) => return None
    };

    let mut out = Vec::new();
    out.extend_from_slice(&sec.randoms.server);
    out.extend_from_slice(&result.get_opaque_payload().unwrap().0);
    Some(out)
  }

  /// Decrypt `ciphertext` and recover the original message.
  fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
    if ciphertext.len() < 32 {
      return None;
    }

    let mut randoms = SessionRandoms::zeroes();
    randoms.we_are_client = true;
    randoms.server.as_mut().write(&ciphertext[..32]).unwrap();

    let sec = SessionSecrets::new_resume(&randoms,
                                         self.suite.get_hash(),
                                         &self.secrets.get_master_secret());
    let cipher = MessageCipher::new(self.suite, &sec);

    let message = Message {
      typ: ContentType::ApplicationData,
      version: ProtocolVersion::TLSv1_2,
      payload: MessagePayload::opaque(ciphertext[32..].to_vec())
    };

    let result = match cipher.decrypt(&message, 0) {
      Ok(m) => m,
      Err(_) => return None
    };

    Some(result.get_opaque_payload().unwrap().0)
  }
}

struct TicketSwitcherState {
  current: Box<ProducesTickets>,
  previous: Option<Box<ProducesTickets>>,
  next_switch_time: i64
}

/// A ticketer that has a 'current' sub-ticketer and a single
/// 'previous' ticketer.  It creates a new ticketer every so
/// often, demoting the current ticketer 
pub struct TicketSwitcher {
  generator: fn() -> Box<ProducesTickets>,
  lifetime: u32,
  state: Mutex<TicketSwitcherState>
}

impl TicketSwitcher {
  /// `lifetime` is in seconds, and is how long the current ticketer
  /// is used to generate new tickets.  Tickets are accepted for no
  /// longer than twice this duration.  `generator` produces a new
  /// `ProducesTickets` implementation.
  pub fn new(lifetime: u32, generator: fn() -> Box<ProducesTickets>) -> TicketSwitcher {
    TicketSwitcher {
      generator: generator,
      lifetime: lifetime,
      state: Mutex::new(
        TicketSwitcherState {
          current: generator(),
          previous: None,
          next_switch_time: time::get_time().sec + lifetime as i64
        }
      )
    }
  }

  fn maybe_roll(&self) {
    let mut state = self.state.lock().unwrap();
    let now = time::get_time().sec;

    if now > state.next_switch_time {
      state.previous = Some(mem::replace(&mut state.current, (self.generator)()));
      state.next_switch_time = now + self.lifetime as i64;
    }
  }
}

impl ProducesTickets for TicketSwitcher {
  fn get_lifetime(&self) -> u32 { self.lifetime * 2 }
  fn enabled(&self) -> bool { true }

  fn encrypt(&self, message: &[u8]) -> Option<Vec<u8>> {
    self.maybe_roll();

    self.state.lock()
      .unwrap()
      .current.encrypt(message)
  }

  fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
    self.maybe_roll();

    let state = self.state.lock().unwrap();
    let rc = state.current.decrypt(ciphertext);

    if rc.is_none() && state.previous.is_some() {
      state.previous.as_ref().unwrap().decrypt(ciphertext)
    } else {
      rc
    }
  }
}

pub struct Ticketer {}

fn generate_inner() -> Box<ProducesTickets> {
  Box::new(StandardCiphersuiteTicketer::new())
}

impl Ticketer {
  /// Make the recommended Ticketer.  This produces tickets
  /// with a 12 hour life and randomly generated keys.
  pub fn new() -> Box<ProducesTickets> {
    Box::new(
      TicketSwitcher::new(6 * 60 * 60, generate_inner)
    )
  }
}
