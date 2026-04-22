# Slow consumer proof

- messages: 100000
- publish_total: 100000
- delivered_to_subscriber: 110000
- subscriber_channel_closed: 1
- decode_to_delivery_drops: 0
- fast_received: 100000

## Assertions

- publisher reached 100000: yes
- slow subscriber dropped after filling: yes
- fast subscriber received 100000: yes
