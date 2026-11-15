//! Types du protocole Creamote, générés depuis `proto/`, et framing des
//! messages sur un flux d'octets.

pub mod framing;

pub mod common {
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/creamote.common.v1.rs"));
    }
}

pub mod rendezvous {
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/creamote.rendezvous.v1.rs"));
    }
}

pub mod session {
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/creamote.session.v1.rs"));
    }
}

/// Version du protocole annoncée lors de l'enregistrement.
pub const PROTOCOL_VERSION: common::v1::Version = common::v1::Version {
    major: 0,
    minor: 1,
    patch: 0,
};
