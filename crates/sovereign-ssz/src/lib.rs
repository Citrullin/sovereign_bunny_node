//! # Sovereign SSZ Wire Types
//!
//! Canonical fixed-offset SSZ serialization types defining the hardware contract
//! for P4/FPGA switches, AF_XDP DMA, and Apache Iggy topics.

pub mod transaction;
pub mod block;
pub mod intent;
pub mod markers;
pub mod range;
pub mod envelope;
pub mod activitypub;
pub mod signal;

pub use transaction::SszTransaction;
pub use block::SszLatticeBlock;
pub use intent::ConfidentialIntent;
pub use markers::{ThresholdEpochMarker, RotationEvent, EpochCheckpoint};
pub use range::{range_key, topic_for_range, RangeKey};
pub use envelope::{wrap_envelope, unwrap_envelope, ENVELOPE_MAGIC, PROTOCOL_VERSION_1, EnvelopeError};
pub use activitypub::{ActivityPubEnvelope, ActivityType};
pub use signal::{SignalEnvelope, SIGNAL_TOPIC_DOMAIN};

