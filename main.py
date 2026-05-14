from inventory_node import InventoryNode
from consensus import ConsensusEngine
from query_system import SecureQuerySystem
from keys import PART1_KEYS, save_key_files
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
    print("\n--- PART 1: Blockchain Record Addition ---")

    while True:
        node_choice = input("Choose originating inventory (A/B/C/D): ").strip().upper()

        if node_choice in ["A", "B", "C", "D"]:
            break
        else:
            print("Invalid choice. Please enter A, B, C or D.")

    record = {
        "item_id": "004",
        "quantity": 12,
        "price": 18,
        "location": node_choice
    }

    print("\nStep 1: Record Creation")
    print("New record:", record)
    print("Originating node: Inventory", node_choice)

    signed_record = nodes[node_choice].sign_record(record)

    print("\nStep 2: Hashing")
    print("SHA-256(record) =")
    print(signed_record["hash_hex"])

    print("\nStep 3: RSA Digital Signature")
    print("signature = hash^d mod n")
    print("Digital signature:")
    print(signed_record["signature"])

    print("\nStep 4: Signature Verification")
    print("Each inventory node verifies the digital signature before voting.")

    consensus = ConsensusEngine(nodes)
    outcome = consensus.run_record_consensus(signed_record)

    print("\nStep 5: Byzantine Fault Tolerant (BFT) Consensus")
    print("Consensus type:", outcome["consensus_type"])
    print("Threshold:", outcome["threshold"])
    print("Votes:", outcome["votes"])
    print(f"Accepted votes: {outcome['yes_votes']}/{outcome['total_nodes']}")

    print("\nFinal decision:")
    print(outcome["decision"])

    if outcome["decision"] == "ACCEPTED":
        print("\nStep 6: Distributed Storage")
        print("Record stored in Inventory A, B, C and D.")


def demo_record_retrieval(nodes):
    print("\n--- PART 2: Secure Query System ---")

    item_id = input("Enter item ID to query: ").strip()
    query_system = SecureQuerySystem(nodes)

    print("\nStep 1: Authorised User Query")
    print("The authorised user submits a query for item", item_id)

    result = query_system.run_secure_query(item_id)

    print("\nStep 2: Local Record Retrieval")
    print("Inventory A, B, C and D retrieve the quantity from local records.")

    print("\nStep 3: Partial Signature Generation")
    print("Each inventory node signs the query result.")
    print("Participating nodes: A, B, C, D")

    print("\nStep 4: Multi-Signature Aggregation")
    print("Partial signatures are combined into one aggregate signature.")
    print("Aggregate signature:")
    print(result["aggregate_signature"])

    print("\nStep 5: Multi-Signature Verification")
    print("Verification equation checks whether the aggregate signature is valid.")
    print("Verification result:", result["verification"]["valid"])

    print("\nStep 6: Secure Delivery")
    print("The verified response is encrypted using the user's public key.")
    print("Encrypted blocks shown in hex:")
    print([hex(block) for block in result["encrypted_blocks"][:5]])

    print("\nStep 7: User Recovery")
    print("The user decrypts the response using their private key.")

    print("\nFinal approved result:")
    print(result["recovered_response"]["result"])


def main():
    save_key_files()
    print("Key parameters generated and stored in separate files.")

    nodes = build_nodes()

    while True:
        print("\nSecure DLT-Based Inventory Management System")
        print("1. Part 1 - Blockchain Record Addition")
        print("2. Part 2 - Secure Query System")
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