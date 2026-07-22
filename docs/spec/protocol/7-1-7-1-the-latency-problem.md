### 7.1 The Latency Problem

Communication delays in the solar system are not engineering failures — they are physics:

| Route                 | One-Way Delay | Round-Trip |
|-----------------------|---------------|------------|
| Earth surface         | < 100 ms      | < 200 ms   |
| Earth-Moon            | 1.3 s         | 2.6 s      |
| Earth-Mars (closest)  | 3 min         | 6 min      |
| Earth-Mars (farthest) | 22 min        | 44 min     |
| Earth-Jupiter         | 33–54 min     | 66–108 min |

No consensus mechanism that requires real-time communication can operate across these delays. A proof-of-work block time of ~10 minutes is barely acceptable for Earth-Moon; it is unusable for Earth-Mars.

