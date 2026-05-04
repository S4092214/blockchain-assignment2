"""Inventory node model for local records, signing, verification, and storage."""

import json
from pathlib import Path

from crypto_utils import derive_rsa_components, rsa_sign, rsa_verify


class InventoryNode:
    def __init__(self, node_id, key_values, data_file):
        self.node_id = node_id
        self.keys = derive_rsa_components(
            key_values["p"], key_values["q"], key_values["e"]
        )
        self.data_file = Path(data_file)
        self.records = self.load_records()

    def load_records(self):
        if not self.data_file.exists():
            return []
        with open(self.data_file, "r", encoding="utf-8") as f:
            return json.load(f)

    def save_records(self):
        with open(self.data_file, "w", encoding="utf-8") as f:
            json.dump(self.records, f, indent=2)

    def sign_record(self, record):
        signature, h_hex = rsa_sign(record, self.keys["d"], self.keys["n"])
        return {
            "record": record,
            "origin": self.node_id,
            "signature": signature,
            "hash_hex": h_hex,
        }

    def verify_signed_record(self, signed_record, public_node):
        ok, h_hex, recovered = rsa_verify(
            signed_record["record"],
            signed_record["signature"],
            public_node.keys["e"],
            public_node.keys["n"],
        )
        return {
            "node": self.node_id,
            "accepted": ok,
            "hash_hex": h_hex,
            "recovered_hash_mod_n": recovered,
        }

    def store_record(self, record):
        existing_ids = [r["item_id"] for r in self.records]
        if record["item_id"] in existing_ids:
            raise ValueError(f"Item {record['item_id']} already exists in Inventory {self.node_id}.")
        self.records.append(record)
        self.save_records()

    def query_quantity(self, item_id):
        for record in self.records:
            if record["item_id"] == item_id:
                return record["quantity"]
        return None
