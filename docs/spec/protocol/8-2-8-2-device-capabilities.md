### 8.2 Device Capabilities

**Minimum viable device: ESP32 ($4) — Profile C (Gateway-Delegated)**
- Authenticates to local gateway via pre-shared symmetric key (established at provisioning)
- Sends readings over secure local channel (BLE, CAN, wired); gateway signs batches with PQC (Profile A/B)
- Stores local readings in flash memory (circular buffer for constrained devices)
- Communicates via Wi-Fi, BLE, LoRa, or CAN bus

**Standard device: Raspberry Pi / industrial controller ($35–$200)**
- Full node capabilities including relay and witness roles
- Local AI inference for anomaly detection (Layer 3)
- Multiple communication interfaces

**Gateway device: edge server ($500+)**
- Aggregates readings from leaf devices
- Provides network connectivity for air-gapped devices
- Runs full DAG synchronization

