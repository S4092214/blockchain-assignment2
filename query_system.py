"""Secure retrieval workflow using Harn-style multi-signature and RSA delivery."""

import json

from crypto_utils import (
    derive_rsa_components,
    harn_partial_signature,
    harn_aggregate,
    harn_verify,
    rsa_encrypt_text,
    rsa_decrypt_text,
)
from keys import PKG_KEY, PROCUREMENT_OFFICER_KEY, INVENTORY_IDENTITIES, INVENTORY_RANDOM_VALUES


class SecureQuerySystem:
    def __init__(self, nodes):
        self.nodes = nodes
        self.pkg = derive_rsa_components(PKG_KEY["p"], PKG_KEY["q"], PKG_KEY["e"])
        self.user = derive_rsa_components(
            PROCUREMENT_OFFICER_KEY["p"],
            PROCUREMENT_OFFICER_KEY["q"],
            PROCUREMENT_OFFICER_KEY["e"],
        )

        # PKG derives each inventory's shadow identity from its public identity.
        self.shadow_identities = {
            node_id: pow(identity, self.pkg["d"], self.pkg["n"])
            for node_id, identity in INVENTORY_IDENTITIES.items()
        }

    def build_query_result(self, item_id):
        quantities = {
            node_id: node.query_quantity(item_id)
            for node_id, node in self.nodes.items()
        }

        values = list(quantities.values())
        consistent = all(value == values[0] for value in values)

        if not consistent:
            result = {
                "item_id": item_id,
                "status": "REJECTED",
                "reason": "Nodes returned inconsistent quantities.",
                "quantities": quantities,
            }
        elif values[0] is None:
            result = {
                "item_id": item_id,
                "status": "NOT_FOUND",
                "quantity": None,
                "quantities": quantities,
            }
        else:
            result = {
                "item_id": item_id,
                "status": "APPROVED",
                "quantity": values[0],
                "quantities": quantities,
            }

        return result

    def run_secure_query(self, item_id):
        result = self.build_query_result(item_id)
        message = json.dumps(result, sort_keys=True)

        partials = {}
        random_values = []
        identities = []

        for node_id in ["A", "B", "C", "D"]:
            partial, R_i, h_hex = harn_partial_signature(
                message,
                INVENTORY_IDENTITIES[node_id],
                self.shadow_identities[node_id],
                INVENTORY_RANDOM_VALUES[node_id],
                self.pkg["n"],
            )
            partials[node_id] = {
                "partial_signature": partial,
                "random_commitment": R_i,
                "hash_hex": h_hex,
            }
            identities.append(INVENTORY_IDENTITIES[node_id])
            random_values.append(INVENTORY_RANDOM_VALUES[node_id])

        aggregate = harn_aggregate(
            [partials[node_id]["partial_signature"] for node_id in ["A", "B", "C", "D"]],
            self.pkg["n"],
        )

        verified, h_hex, left, right = harn_verify(
            message,
            aggregate,
            identities,
            random_values,
            self.pkg["e"],
            self.pkg["n"],
        )

        protected_response = {
            "result": result,
            "aggregate_signature": aggregate,
            "multisig_verified_before_delivery": verified,
        }
        plaintext = json.dumps(protected_response, sort_keys=True)

        cipher_blocks = rsa_encrypt_text(plaintext, self.user["e"], self.user["n"])
        recovered_plaintext = rsa_decrypt_text(cipher_blocks, self.user["d"], self.user["n"])
        recovered = json.loads(recovered_plaintext)

        return {
            "query_message": message,
            "partials": partials,
            "aggregate_signature": aggregate,
            "verification": {
                "valid": verified,
                "hash_hex": h_hex,
                "left_S_power_e": left,
                "right_expected_value": right,
            },
            "encrypted_blocks": cipher_blocks,
            "recovered_response": recovered,
        }
