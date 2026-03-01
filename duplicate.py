import hashlib
from pathlib import Path
from collections import defaultdict

def file_hash(path):
    hasher = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)
    return hasher.hexdigest()

def folder_search():
    folder_path = str(input("Enter the folder path: "))
    path = Path(folder_path)

    if not path.exists():
        print("Error: That path does not exist.")
        folder_search_menu()
        return
    if not path.is_dir():
        print("Error: Path is not a folder.")
        folder_search_menu()
        return

    hash_map = defaultdict(list)
    full_path = str(input("Do you want the full path? (y/n): ")).strip().lower() == "y"

    print("Searching for duplicates...")

    for file in path.iterdir():
        if file.is_file():
            try:
                h = file_hash(file)
                hash_map[h].append(file)
            except (PermissionError, OSError) as e:
                print(f"  Skipping {file.name}: {e}")

    for h, files in hash_map.items():
        if len(files) > 1:
            print("Duplicate group found:")
            for file in files:
                if full_path:
                    print(f"  {file}")
                else:
                    print(str(f"  {file.parent.name}\{file.name}"))

    folder_search_menu()

def folder_search_menu():
    choice = str(input("Do you want to search? (y/n): "))
    if choice == "y":
        folder_search()
    else:
        print("Exiting...")

folder_search_menu()