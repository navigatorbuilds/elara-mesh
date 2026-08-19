### 8.3 Supported Protocols

The Elara Protocol integrates with standard IoT communication protocols:

| Protocol         | Use Case                         | Integration                             |
|------------------|----------------------------------|-----------------------------------------|
| **MQTT**         | Lightweight pub/sub messaging    | Signed payloads as MQTT messages        |
| **CoAP**         | Constrained RESTful protocol     | Validation records as CoAP resources    |
| **gRPC**         | High-performance RPC             | Native Elara service definitions        |
| **HTTP/HTTPS**   | IoT-device → gateway integration only (NOT node-to-node — see §4.7) | Profile C delegated signing: device posts unsigned readings to a trusted gateway over HTTPS; gateway signs with PQ identity and forwards to the DAM via ElaraPQ |
| **BLE**          | Short-range device communication | Signed readings via BLE characteristics |
| **CAN**          | Automotive/industrial bus        | Signed frames on CAN bus                |
| **LoRa/LoRaWAN** | Long-range, low-power            | Compact validation records for LPWAN    |

