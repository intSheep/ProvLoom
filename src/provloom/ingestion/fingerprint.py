from __future__ import annotations

import hashlib

from provloom.ingestion.interfaces import Fingerprinter


class Sha256Fingerprinter(Fingerprinter):
    def compute(self, tenant_scope: str, source_id: str, raw_payload: str) -> str:
        # Canonicalize trailing newline differences while keeping tenant + source isolation.
        canonical = raw_payload.rstrip("\r\n")
        material = f"{tenant_scope}\0{source_id}\0{canonical}".encode()
        return hashlib.sha256(material).hexdigest()
