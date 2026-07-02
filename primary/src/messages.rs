// Copyright(C) Facebook, Inc. and its affiliates.
use crate::error::{DagError, DagResult};
use crate::primary::Round;
use config::{Committee, WorkerId};
use crypto::{Digest, Hash, PublicKey, Signature, SignatureService};
use ed25519_dalek::Digest as _;
use ed25519_dalek::Sha512;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::convert::TryInto;
use std::fmt;

pub type Transaction = Vec<u8>;

pub fn transaction_digest(transaction: &Transaction) -> Digest {
    Digest(
        Sha512::digest(transaction).as_slice()[..32]
            .try_into()
            .unwrap(),
    )
}

pub fn transaction_sent_at_micros(transaction: &Transaction) -> Option<u64> {
    if transaction.len() <= 16 {
        return None;
    }
    let sent_at = u64::from_be_bytes(transaction[9..17].try_into().ok()?);
    (sent_at != 0).then_some(sent_at)
}

#[derive(Clone, Serialize, Deserialize)]
pub enum Payload {
    Narwhal(BTreeMap<Digest, WorkerId>),
    Direct(Vec<Transaction>),
}

impl Payload {
    pub fn new(use_narwhal: bool) -> Self {
        if use_narwhal {
            Self::Narwhal(BTreeMap::new())
        } else {
            Self::Direct(Vec::new())
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Self::Narwhal(payload) => payload.is_empty(),
            Self::Direct(payload) => payload.is_empty(),
        }
    }

    pub fn size(&self) -> usize {
        match self {
            Self::Narwhal(payload) => payload.keys().map(|x| x.size()).sum(),
            Self::Direct(payload) => payload.iter().map(|x| x.len()).sum(),
        }
    }

    pub fn push_narwhal(&mut self, digest: Digest, worker_id: WorkerId) {
        match self {
            Self::Narwhal(payload) => {
                payload.insert(digest, worker_id);
            }
            Self::Direct(_) => panic!("cannot add Narwhal digest to direct payload"),
        }
    }

    pub fn push_transaction(&mut self, transaction: Transaction) {
        match self {
            Self::Narwhal(_) => panic!("cannot add transaction to Narwhal payload"),
            Self::Direct(payload) => payload.push(transaction),
        }
    }

    pub fn narwhal(&self) -> Option<&BTreeMap<Digest, WorkerId>> {
        match self {
            Self::Narwhal(payload) => Some(payload),
            Self::Direct(_) => None,
        }
    }

    pub fn transactions(&self) -> Option<&[Transaction]> {
        match self {
            Self::Narwhal(_) => None,
            Self::Direct(payload) => Some(payload),
        }
    }
}

impl Default for Payload {
    fn default() -> Self {
        Self::Narwhal(BTreeMap::new())
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct Header {
    pub author: PublicKey,
    pub round: Round,
    pub payload: Payload,
    pub parents: BTreeSet<Digest>,
    pub id: Digest,
    pub signature: Signature,
}

impl Header {
    pub async fn new(
        author: PublicKey,
        round: Round,
        payload: Payload,
        parents: BTreeSet<Digest>,
        signature_service: &mut SignatureService,
    ) -> Self {
        let header = Self {
            author,
            round,
            payload,
            parents,
            id: Digest::default(),
            signature: Signature::default(),
        };
        let id = header.digest();
        let signature = signature_service.request_signature(id.clone()).await;
        Self {
            id,
            signature,
            ..header
        }
    }

    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        // Ensure the header id is well formed.
        ensure!(self.digest() == self.id, DagError::InvalidHeaderId);

        // Ensure the authority has voting rights.
        let voting_rights = committee.stake(&self.author);
        ensure!(voting_rights > 0, DagError::UnknownAuthority(self.author));

        // Ensure all worker ids are correct when the header carries Narwhal batch references.
        if let Payload::Narwhal(payload) = &self.payload {
            for worker_id in payload.values() {
                committee
                    .worker(&self.author, &worker_id)
                    .map_err(|_| DagError::MalformedHeader(self.id.clone()))?;
            }
        }

        // Check the signature.
        self.signature
            .verify(&self.id, &self.author)
            .map_err(DagError::from)
    }
}

impl Hash for Header {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(&self.author);
        hasher.update(self.round.to_le_bytes());
        match &self.payload {
            Payload::Narwhal(payload) => {
                hasher.update(b"narwhal");
                for (x, y) in payload {
                    hasher.update(x);
                    hasher.update(y.to_le_bytes());
                }
            }
            Payload::Direct(payload) => {
                hasher.update(b"direct");
                for transaction in payload {
                    hasher.update((transaction.len() as u64).to_le_bytes());
                    hasher.update(transaction);
                }
            }
        }
        for x in &self.parents {
            hasher.update(x);
        }
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: B{}({}, {})",
            self.id,
            self.round,
            self.author,
            self.payload.size(),
        )
    }
}

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "B{}({})", self.round, self.author)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Vote {
    pub id: Digest,
    pub round: Round,
    pub origin: PublicKey,
    pub author: PublicKey,
    pub signature: Signature,
}

impl Vote {
    pub async fn new(
        header: &Header,
        author: &PublicKey,
        signature_service: &mut SignatureService,
    ) -> Self {
        let vote = Self {
            id: header.id.clone(),
            round: header.round,
            origin: header.author,
            author: *author,
            signature: Signature::default(),
        };
        let signature = signature_service.request_signature(vote.digest()).await;
        Self { signature, ..vote }
    }

    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        // Ensure the authority has voting rights.
        ensure!(
            committee.stake(&self.author) > 0,
            DagError::UnknownAuthority(self.author)
        );

        // Check the signature.
        self.signature
            .verify(&self.digest(), &self.author)
            .map_err(DagError::from)
    }
}

impl Hash for Vote {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(&self.id);
        hasher.update(self.round.to_le_bytes());
        hasher.update(&self.origin);
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Vote {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: V{}({}, {})",
            self.digest(),
            self.round,
            self.author,
            self.id
        )
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct Certificate {
    pub header: Header,
    pub votes: Vec<(PublicKey, Signature)>,
}

impl Certificate {
    pub fn genesis(committee: &Committee) -> Vec<Self> {
        committee
            .authorities
            .keys()
            .map(|name| Self {
                header: Header {
                    author: *name,
                    ..Header::default()
                },
                ..Self::default()
            })
            .collect()
    }

    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        // Genesis certificates are always valid.
        if Self::genesis(committee).contains(self) {
            return Ok(());
        }

        // Check the embedded header.
        self.header.verify(committee)?;

        // Ensure the certificate has a quorum.
        let mut weight = 0;
        let mut used = HashSet::new();
        for (name, _) in self.votes.iter() {
            ensure!(!used.contains(name), DagError::AuthorityReuse(*name));
            let voting_rights = committee.stake(name);
            ensure!(voting_rights > 0, DagError::UnknownAuthority(*name));
            used.insert(*name);
            weight += voting_rights;
        }
        ensure!(
            weight >= committee.quorum_threshold(),
            DagError::CertificateRequiresQuorum
        );

        // Check the signatures.
        Signature::verify_batch(&self.digest(), &self.votes).map_err(DagError::from)
    }

    pub fn round(&self) -> Round {
        self.header.round
    }

    pub fn origin(&self) -> PublicKey {
        self.header.author
    }
}

impl Hash for Certificate {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(&self.header.id);
        hasher.update(self.round().to_le_bytes());
        hasher.update(&self.origin());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: C{}({}, {})",
            self.digest(),
            self.round(),
            self.origin(),
            self.header.id
        )
    }
}

impl PartialEq for Certificate {
    fn eq(&self, other: &Self) -> bool {
        let mut ret = self.header.id == other.header.id;
        ret &= self.round() == other.round();
        ret &= self.origin() == other.origin();
        ret
    }
}
