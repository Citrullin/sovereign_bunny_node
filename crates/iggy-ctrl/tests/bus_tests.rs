use sovereign_iggy_ctrl::{
    IggyMessageBus, IggyProducer, IggyConsumer,
    TOPIC_RANGE_0, topic_for_range_key
};

#[tokio::test]
async fn test_iggy_bus_pub_sub() {
    let bus = IggyMessageBus::new();
    let mut consumer = IggyConsumer::new(bus.subscribe(TOPIC_RANGE_0).await);
    let producer = IggyProducer::new(bus.clone());

    let payload = vec![0x11, 0x22, 0x33, 0x44];
    producer.send_ssz_intent(TOPIC_RANGE_0, payload.clone()).await.unwrap();

    let received = consumer.recv().await.unwrap();
    assert_eq!(received.as_ref(), payload.as_slice());
}

#[tokio::test]
async fn test_topic_routing() {
    assert_eq!(topic_for_range_key(0x1000), TOPIC_RANGE_0);
    assert_eq!(topic_for_range_key(0x5000), "range-0x4000-0x7FFF");
    assert_eq!(topic_for_range_key(0x9000), "range-0x8000-0xBFFF");
    assert_eq!(topic_for_range_key(0xD000), "range-0xC000-0xFFFF");
}
