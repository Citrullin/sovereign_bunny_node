use std::sync::Arc;
use tokio::sync::broadcast;
use bytes::Bytes;
use std::collections::HashMap;
use tokio::sync::RwLock;

/// Thread-safe in-memory message bus implementing the Iggy partition semantics for testing and local runtimes.
#[derive(Clone, Debug)]
pub struct IggyMessageBus {
    topics: Arc<RwLock<HashMap<String, broadcast::Sender<Bytes>>>>,
}

impl Default for IggyMessageBus {
    fn default() -> Self {
        Self::new()
    }
}

impl IggyMessageBus {
    pub fn new() -> Self {
        Self {
            topics: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Retrieves or initializes a broadcast channel for a given topic
    async fn get_or_create_sender(&self, topic: &str) -> broadcast::Sender<Bytes> {
        let mut map = self.topics.write().await;
        if let Some(sender) = map.get(topic) {
            sender.clone()
        } else {
            let (tx, _rx) = broadcast::channel(10000);
            map.insert(topic.to_string(), tx.clone());
            tx
        }
    }

    /// Publish a message to a topic
    pub async fn publish(&self, topic: &str, payload: Bytes) -> Result<(), String> {
        let sender = self.get_or_create_sender(topic).await;
        let _ = sender.send(payload);
        Ok(())
    }

    /// Subscribe to a topic
    pub async fn subscribe(&self, topic: &str) -> broadcast::Receiver<Bytes> {
        let sender = self.get_or_create_sender(topic).await;
        sender.subscribe()
    }
}

/// Helper producer wrapper
#[derive(Clone, Debug)]
pub struct IggyProducer {
    bus: IggyMessageBus,
}

impl IggyProducer {
    pub fn new(bus: IggyMessageBus) -> Self {
        Self { bus }
    }

    pub async fn send_ssz_intent(&self, topic: &str, payload: Vec<u8>) -> Result<(), String> {
        self.bus.publish(topic, Bytes::from(payload)).await
    }
}

/// Helper consumer wrapper
pub struct IggyConsumer {
    rx: broadcast::Receiver<Bytes>,
}

impl IggyConsumer {
    pub fn new(rx: broadcast::Receiver<Bytes>) -> Self {
        Self { rx }
    }

    pub async fn recv(&mut self) -> Result<Bytes, broadcast::error::RecvError> {
        self.rx.recv().await
    }
}
