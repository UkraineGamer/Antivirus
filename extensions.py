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
        yield file.name

def suspicious_file():
    safe_files = []
    warning_files = []
    dangerous_files = []

    folder_path = str(input("Enter the folder path: "))
    path = Path(folder_path)

    for file in path.glob('**/*'):
        if file.is_file():
            suffixes = file.suffixes
            if len(suffixes) > 1:
                dangerous_files.append(file)
            elif file.suffix in SUSPICIOUS_EXTENSIONS:
                warning_files.append(file)
            else:
                safe_files.append(file)

    print('safe files:\n')
    for f in print_file(safe_files):
        print('-',f)
    print('potentialy dangerous files:\n')
    for f in print_file(warning_files):
        print('-',f)
    print('dangerous files:\n')
    for f in print_file(dangerous_files):
        print('-',f)

suspicious_file()