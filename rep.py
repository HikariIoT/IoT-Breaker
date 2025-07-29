import json
import os

DATA_FILE = "re_playground_progress.json"

challenges = [
    {
        "id": 1,
        "title": "Basic Crackme",
        "category": "Crackme",
        "difficulty": "Easy",
        "description": "A simple password check challenge using XOR encryption.",
        "tags": ["beginner", "password", "xor"],
    },
    {
        "id": 2,
        "title": "Obfuscated Calculator",
        "category": "Obfuscation",
        "difficulty": "Medium",
        "description": "Calculator app with heavy code obfuscation and anti-debug tricks.",
        "tags": ["obfuscation", "anti-debug", "medium"],
    },
    {
        "id": 3,
        "title": "Packed Malware Sample",
        "category": "Reverse Engineering",
        "difficulty": "Hard",
        "description": "Reverse engineer a packed binary and find the hidden payload.",
        "tags": ["packing", "malware", "advanced"],
    },
    {
        "id": 4,
        "title": "Protocol Sniffer",
        "category": "Reverse Engineering",
        "difficulty": "Medium",
        "description": "Analyze an unknown binary protocol with reverse engineering.",
        "tags": ["protocol", "analysis", "medium"],
    },
    {
        "id": 5,
        "title": "Advanced Anti-Debug",
        "category": "Obfuscation",
        "difficulty": "Hard",
        "description": "Crack a binary employing multiple anti-debugging techniques.",
        "tags": ["anti-debug", "obfuscation", "hard"],
    },
]

def load_progress():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_progress(progress):
    with open(DATA_FILE, "w") as f:
        json.dump(progress, f, indent=4)

def list_challenges(progress, filter_by=None):
    print("\nAvailable Challenges:")
    for c in challenges:
        if filter_by and filter_by.lower() not in c["category"].lower() and filter_by.lower() not in c["difficulty"].lower():
            continue
        status = "SOLVED" if progress.get(str(c["id"]), False) else "UNSOLVED"
        print(f"{c['id']}. [{status}] {c['title']} ({c['category']} - {c['difficulty']})")
    print()

def show_challenge_details(challenge_id):
    c = next((x for x in challenges if x["id"] == challenge_id), None)
    if not c:
        print("Challenge not found.\n")
        return
    print(f"\nTitle      : {c['title']}")
    print(f"Category   : {c['category']}")
    print(f"Difficulty : {c['difficulty']}")
    print(f"Description: {c['description']}")
    print(f"Tags       : {', '.join(c['tags'])}\n")

def mark_solved(progress, challenge_id):
    progress[str(challenge_id)] = True
    save_progress(progress)
    print("Marked as solved!\n")

def search_challenges(keyword):
    results = [c for c in challenges if keyword.lower() in c["title"].lower() or
               keyword.lower() in c["description"].lower() or
               keyword.lower() in c["category"].lower() or
               keyword.lower() in c["difficulty"].lower() or
               keyword.lower() in " ".join(c["tags"]).lower()]
    return results

def main():
    print("Welcome to RE-Playground - Reverse Engineering Challenge Manager\n")
    progress = load_progress()

    while True:
        print("Commands: list, details <id>, solve <id>, search <keyword>, exit")
        cmd = input("RE> ").strip()

        if cmd == "exit":
            print("Goodbye!")
            break
        elif cmd == "list":
            list_challenges(progress)
        elif cmd.startswith("list "):
            _, filter_by = cmd.split(" ", 1)
            list_challenges(progress, filter_by=filter_by)
        elif cmd.startswith("details "):
            try:
                challenge_id = int(cmd.split()[1])
                show_challenge_details(challenge_id)
            except:
                print("Invalid challenge id.\n")
        elif cmd.startswith("solve "):
            try:
                challenge_id = int(cmd.split()[1])
                mark_solved(progress, challenge_id)
            except:
                print("Invalid challenge id.\n")
        elif cmd.startswith("search "):
            keyword = cmd.split(" ", 1)[1]
            results = search_challenges(keyword)
            if not results:
                print("No challenges found.\n")
            else:
                print(f"\nSearch results for '{keyword}':")
                for c in results:
                    status = "SOLVED" if progress.get(str(c["id"]), False) else "UNSOLVED"
                    print(f"{c['id']}. [{status}] {c['title']} ({c['category']} - {c['difficulty']})")
                print()
        else:
            print("Unknown command. Try again.\n")

if __name__ == "__main__":
    main()
