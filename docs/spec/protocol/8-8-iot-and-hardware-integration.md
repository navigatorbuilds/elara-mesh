## 8. IoT and Hardware Integration

*Implementation-status note: Section 8 describes the IoT design. The Rust runtime implements Profile C delegation records: a gateway identity authorizes and revokes child devices and signs records on their behalf, and a record signed with a registered child's own key is rejected. The hardware attestation level a gateway must meet is self-declared in its record's metadata; no hardware evidence is checked. The node serves an HTTP REST API. The MQTT, CoAP, gRPC, BLE, CAN and LoRaWAN integrations in Section 8.3, the device-to-gateway link, and the gateway-side firmware checks, anomaly detection and key rotation in Section 8.6 are design-stage.*

