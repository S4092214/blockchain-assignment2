"""Simplified PBFT-style consensus for four simulated inventory nodes."""


class ConsensusEngine:
    """
    Four known inventory nodes vote on whether the record is valid.

    This is a simplified PBFT-style majority decision:
    - each node verifies the originating node's RSA signature;
    - a record is accepted if at least 3 out of 4 nodes approve;
    - after acceptance, every node stores the same record.
    """

    def __init__(self, nodes, threshold=3):
        self.nodes = nodes
        self.threshold = threshold

    def run_record_consensus(self, signed_record):
        origin_id = signed_record["origin"]
        origin_node = self.nodes[origin_id]

        votes = {}
        details = []

        for node_id, node in self.nodes.items():
            result = node.verify_signed_record(signed_record, origin_node)
            votes[node_id] = result["accepted"]
            details.append(result)

        yes_votes = sum(1 for vote in votes.values() if vote)
        decision = yes_votes >= self.threshold

        if decision:
            for node in self.nodes.values():
                try:
                    node.store_record(signed_record["record"])
                except ValueError:
                    # Already stored during a previous demo run. Keep system usable.
                    pass

        return {
            "votes": votes,
            "yes_votes": yes_votes,
            "total_nodes": len(self.nodes),
            "threshold": self.threshold,
            "consensus_type": "PBFT / BFT",
            "fault_tolerance": "System tolerates 1 faulty node out of 4",
            "decision": "ACCEPTED" if decision else "REJECTED",
            "details": details,
        }
