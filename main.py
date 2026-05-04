from inventory_node import InventoryNode
from consensus import ConsensusEngine
from query_system import SecureQuerySystem
from keys import PART1_KEYS
import os


def build_nodes():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(base_dir, "data")

    return {
        "A": InventoryNode("A", PART1_KEYS["A"], os.path.join(data_dir, "inventory_A.json")),
        "B": InventoryNode("B", PART1_KEYS["B"], os.path.join(data_dir, "inventory_B.json")),
        "C": InventoryNode("C", PART1_KEYS["C"], os.path.join(data_dir, "inventory_C.json")),
        "D": InventoryNode("D", PART1_KEYS["D"], os.path.join(data_dir, "inventory_D.json")),
    }


def demo_record_insertion(nodes):
    print("\n--- Secure Record Insertion ---")

    record = {
        "item_id": "004",
        "quantity": 12,
        "price": 18,
        "location": "A"
    }

    print("New record:", record)
    print("Originating node: Inventory A")

    signed_record = nodes["A"].sign_record(record)

    print("\nHash:")
    print(signed_record["hash_hex"])

    print("\nDigital signature:")
    print(signed_record["signature"])

    consensus = ConsensusEngine(nodes)
    outcome = consensus.run_record_consensus(signed_record)

    print("\nConsensus votes:")
    print(outcome["votes"])

    print("\nFinal decision:")
    print(outcome["decision"])

    if outcome["decision"] == "ACCEPTED":
        print("\nRecord stored in Inventory A, B, C and D.")


def demo_record_retrieval(nodes):
    print("\n--- Secure Record Retrieval ---")

    item_id = "002"
    query_system = SecureQuerySystem(nodes)

    result = query_system.run_secure_query(item_id)

    print("Query item:", item_id)

    print("\nQuery result:")
    print(result["query_message"])

    print("\nPartial signatures:")
    print("Inventory A, B, C and D each signed the query result.")

    print("\nAggregate signature:")
    print(result["aggregate_signature"])

    print("\nMulti-signature verification:")
    print(result["verification"]["valid"])

    print("\nEncrypted response blocks shown in hex:")
    print([hex(block) for block in result["encrypted_blocks"][:5]])

    print("\nRecovered response after decryption:")
    print(result["recovered_response"])


def main():
    nodes = build_nodes()

    while True:
        print("\nSecure DLT-Based Inventory Management System")
        print("1. Demonstrate secure record insertion")
        print("2. Demonstrate secure record retrieval")
        print("3. Exit")

        choice = input("Choose an option: ").strip()

        if choice == "1":
            demo_record_insertion(nodes)
        elif choice == "2":
            demo_record_retrieval(nodes)
        elif choice == "3":
            print("Exiting system.")
            break
        else:
            print("Invalid choice. Please choose 1, 2 or 3.")


if __name__ == "__main__":
    main()