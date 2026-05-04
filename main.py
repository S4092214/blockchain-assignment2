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

    print("\nEach inventory node verifies the digital signature before voting.")
    
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

    print("\nStep 1: Authorised user submits query for item", item_id)

    result = query_system.run_secure_query(item_id)

    print("\nStep 2: Inventory A, B, C and D retrieve local data")

    print("\nStep 3: Each node generates a partial signature")
    print("4 nodes participated")

    print("\nStep 4: Partial signatures are combined")
    print("Aggregate signature:", result["aggregate_signature"])

    print("\nStep 5: Multi-signature verification result:")
    print(result["verification"]["valid"])

    print("\nStep 6: Response encrypted for the user")
    print("Encrypted blocks (hex):", [hex(b) for b in result["encrypted_blocks"][:5]])

    print("\nStep 7: User decrypts and verifies the result")

    print("\nFinal result:")
    print(result["recovered_response"]["result"])


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