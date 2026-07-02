// Copyright(C) Facebook, Inc. and its affiliates.
use crate::messages::{Certificate, Header, Payload};
#[cfg(feature = "benchmark")]
use crate::messages::{transaction_digest, transaction_sent_at_micros};
use crate::primary::{ProposerMessage, Round};
use config::Committee;
use crypto::Hash as _;
use crypto::{Digest, PublicKey, SignatureService};
use log::debug;
#[cfg(feature = "benchmark")]
use log::info;
#[cfg(feature = "benchmark")]
use std::convert::TryInto as _;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::{sleep, Duration, Instant};

#[cfg(test)]
#[path = "tests/proposer_tests.rs"]
pub mod proposer_tests;

/// The proposer creates new headers and send them to the core for broadcasting and further processing.
pub struct Proposer {
    /// The public key of this primary.
    name: PublicKey,
    /// Service to sign headers.
    signature_service: SignatureService,
    /// Whether headers carry Narwhal batch digests or transactions directly.
    use_narwhal: bool,
    /// The size of the headers' payload.
    header_size: usize,
    /// The maximum delay to wait for batches' digests.
    max_header_delay: u64,

    /// Receives the parents to include in the next header (along with their round number).
    rx_core: Receiver<(Vec<Digest>, Round)>,
    /// Receives payload items from our workers.
    rx_workers: Receiver<ProposerMessage>,
    /// Sends newly created headers to the `Core`.
    tx_core: Sender<Header>,

    /// The current round of the dag.
    round: Round,
    /// Holds the certificates' ids waiting to be included in the next header.
    last_parents: Vec<Digest>,
    /// Holds the payload waiting to be included in the next header.
    payload: Payload,
    /// Keeps track of the size (in bytes) of payload that we received so far.
    payload_size: usize,
}

impl Proposer {
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        name: PublicKey,
        committee: &Committee,
        signature_service: SignatureService,
        use_narwhal: bool,
        header_size: usize,
        max_header_delay: u64,
        rx_core: Receiver<(Vec<Digest>, Round)>,
        rx_workers: Receiver<ProposerMessage>,
        tx_core: Sender<Header>,
    ) {
        let genesis = Certificate::genesis(committee)
            .iter()
            .map(|x| x.digest())
            .collect();

        tokio::spawn(async move {
            Self {
                name,
                signature_service,
                use_narwhal,
                header_size,
                max_header_delay,
                rx_core,
                rx_workers,
                tx_core,
                round: 1,
                last_parents: genesis,
                payload: Payload::new(use_narwhal),
                payload_size: 0,
            }
            .run()
            .await;
        });
    }

    async fn make_header(&mut self) {
        // Make a new header.
        let header = Header::new(
            self.name,
            self.round,
            std::mem::replace(&mut self.payload, Payload::new(self.use_narwhal)),
            self.last_parents.drain(..).collect(),
            &mut self.signature_service,
        )
        .await;
        debug!("Created {:?}", header);

        #[cfg(feature = "benchmark")]
        match &header.payload {
            Payload::Narwhal(payload) => {
                for digest in payload.keys() {
                    // NOTE: This log entry is used to compute performance.
                    info!("Created {} -> {:?}", header, digest);
                }
            }
            Payload::Direct(payload) => {
                for transaction in payload {
                    let digest = transaction_digest(transaction);
                    // NOTE: This log entry is used to compute performance.
                    info!("Created {} -> {:?}", header, digest);
                    // NOTE: This log entry is used to compute performance.
                    match transaction_sent_at_micros(transaction) {
                        Some(sent_at) => info!(
                            "Transaction {:?} contains {} B sent at {} us",
                            digest,
                            transaction.len(),
                            sent_at
                        ),
                        None => info!("Transaction {:?} contains {} B", digest, transaction.len()),
                    }
                    if transaction.first() == Some(&0u8) && transaction.len() > 8 {
                        if let Ok(id) = transaction[1..9].try_into() {
                            // NOTE: This log entry is used to compute performance.
                            info!("Transaction {:?} contains sample tx {}", digest, u64::from_be_bytes(id));
                        }
                    }
                }
            }
        }

        // Send the new header to the `Core` that will broadcast and process it.
        self.tx_core
            .send(header)
            .await
            .expect("Failed to send header");
    }

    // Main loop listening to incoming messages.
    pub async fn run(&mut self) {
        debug!("Dag starting at round {}", self.round);

        let timer = sleep(Duration::from_millis(self.max_header_delay));
        tokio::pin!(timer);

        loop {
            // Check if we can propose a new header. We propose a new header when one of the following
            // conditions is met:
            // 1. We have a quorum of certificates from the previous round and enough batches' digests;
            // 2. We have a quorum of certificates from the previous round and the specified maximum
            // inter-header delay has passed.
            let enough_parents = !self.last_parents.is_empty();
            let enough_digests = self.payload_size >= self.header_size;
            let timer_expired = timer.is_elapsed();
            if (timer_expired || enough_digests) && enough_parents {
                // Make a new header.
                self.make_header().await;
                self.payload_size = 0;

                // Reschedule the timer.
                let deadline = Instant::now() + Duration::from_millis(self.max_header_delay);
                timer.as_mut().reset(deadline);
            }

            tokio::select! {
                Some((parents, round)) = self.rx_core.recv() => {
                    if round < self.round {
                        continue;
                    }

                    // Advance to the next round.
                    self.round = round + 1;
                    debug!("Dag moved to round {}", self.round);

                    // Signal that we have enough parent certificates to propose a new header.
                    self.last_parents = parents;
                }
                Some(message) = self.rx_workers.recv() => {
                    match message {
                        ProposerMessage::Batch(digest, worker_id) => {
                            if self.use_narwhal {
                                self.payload_size += digest.size();
                                self.payload.push_narwhal(digest, worker_id);
                            }
                        }
                        ProposerMessage::Transaction(transaction) => {
                            if !self.use_narwhal {
                                self.payload_size += transaction.len();
                                self.payload.push_transaction(transaction);
                            }
                        }
                    }
                }
                () = &mut timer => {
                    // Nothing to do.
                }
            }
        }
    }
}
