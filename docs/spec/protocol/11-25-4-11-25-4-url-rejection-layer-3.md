#### 11.25.4 URL Rejection (Layer 3)

All text fields reject URLs matching these patterns (case-insensitive):

- `http://`, `https://` — web links to external content
- `ftp://` — file transfer links
- `data:` — base64-encoded inline content (images, documents)
- `javascript:` — cross-site scripting vectors
- `magnet:` — torrent/peer-to-peer content links

This prevents records from serving as a link directory for illegal content. A record cannot contain a URL pointing to child exploitation material, a drug marketplace, or a terrorism recruitment site. The protocol is structurally unable to function as a content indexing or referral system.

