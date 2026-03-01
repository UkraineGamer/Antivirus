import os
import pathlib
from pathlib import Path



SUSPICIOUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".com", ".scr", ".pif",
    ".msi", ".cpl", ".js", ".vbs", ".ps1", ".hta",
    ".docm", ".xlsm", ".pptm", ".lnk"
} 

def print_file(files):
    for file in files:
        print(file)

def suspicious_file():
    safe_files = []
    warning_files = []
    dangerous_files = []

    folder_path = str(input("Enter the folder path: "))
    path = Path(folder_path)

    for file in path.glob('**/*'):
        if file.is_file():
            suffixes = file.suffixes
            if file.suffix in SUSPICIOUS_EXTENSIONS:
                warning_files.append(file)
            elif len(suffixes) > 1:
                dangerous_files.append(file)
            else:
                safe_files.append(file)

    print('safe files:\n', print_file(safe_files))
    print('potantialy dangerous files:\n', print_file(warning_files))
    print('dangerous files:\n', print_file(dangerous_files))

suspicious_file()