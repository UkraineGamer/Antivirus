import os
from os.path import getsize, join
import pathlib
from pathlib import Path

# for root, dirs, files in os.walking(''):
#     total_size = sum(getsize(join(root, name)) for name in files)
#     print(root, total_size)

dir_sizes = dict()

folder_path = input(str("paste your folder route: "))
path = pathlib.Path(folder_path)

if path.exists() and path.is_dir():
    print(f"folder hiden: {path}")
    for file in path.iterdir():
        print(f"File/folder: {file.name}")
else:
    print("This path is nonexistent folder.")

for filename in os.listdir(folder_path):
    full_path = os.path.join(folder_path, filename)

    if os.path.isfile(full_path):
        size = os.path.getsize(full_path)
        print(f"{filename} — {size} байт")
