### 8.3 Supported Protocols

The Elara Protocol is designed to integrate with standard IoT communication protocols. Only the HTTP/HTTPS REST API is implemented today; the other integrations are design-stage:

| Protocol         | Use Case                         | Integration                             |
|------------------|----------------------------------|-----------------------------------------|
| **MQTT**         | Lightweight pub/sub messaging    | Signed payloads as MQTT messages        |
| **CoAP**         | Constrained RESTful protocol     | Validation records as CoAP resources    |
| **gRPC**         | High-performance RPC             | Native Elara service definitions        |
| **HTTP/HTTPS**   | General web integration          | REST API for validation records         |
| **BLE**          | Short-range device communication | Signed readings via BLE characteristics |
| **CAN**          | Automotive/industrial bus        | Signed frames on CAN bus                |
| **LoRa/LoRaWAN** | Long-range, low-power            | Compact validation records for LPWAN    |

