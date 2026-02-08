import hashlib
from pathlib import Path

def folder_search():
    folder_path = str(input("Enter the folder path: "))
    path = Path(folder_path)

    choice = str(input("Do you want the full path? (y/n): "))
    if choice == "y":
        for file in path.iterdir():
            print(file)
    else:
        for file in path.iterdir():
            print(f"{file.parent.name}/{file.name}")
    folder_search_menu()

def folder_search_menu():
    choice = str(input("Do you want to search? (y/n): "))
    if choice == "y":
        folder_search()
    else:
        print("Exiting...")

folder_search_menu()