import os

def replace_in_file(filepath):
    # Try reading as utf-8, else fall back to local encoding
    content = None
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
    except UnicodeDecodeError:
        try:
            with open(filepath, 'r', encoding='latin-1') as f:
                content = f.read()
        except Exception as e:
            print(f"Skipping {filepath} (Cannot read): {e}")
            return False
    except Exception as e:
        print(f"Skipping {filepath}: {e}")
        return False

    old_content = content
    # Case insensitive replacements
    content = content.replace("ZYZOR", "COGNIWAS")
    content = content.replace("Zyzor", "CogniWAS")
    content = content.replace("zyzor", "cogniwas")

    if old_content != content:
        # Try to write back in utf-8, fallback to latin1 if we loaded it in latin1 but we probably want it as it was if possible
        # Actually it's simpler to just write it as utf-8 or whatever it was
        try:
            with open(filepath, 'w', encoding='utf-8', newline='') as f:
                f.write(content)
            return True
        except Exception as e:
            print(f"Error writing to {filepath}: {e}")
            return False
    return False

def main():
    directory = r"d:\New folder (2)\ZYZOR"
    ignore_dirs = {'.git', '__pycache__', '.pytest_cache', 'venv', 'env', '.venv', '.vscode', '.idea', '.gemini'}
    ignore_files = {'replace_script.py'}

    changed_files_count = 0
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        for file in files:
            if file in ignore_files or file.endswith(('.pyc', '.pyo', '.pyd', '.dll', '.exe', '.png', '.jpg', '.jpeg', '.gif', '.pdf')):
                continue
            filepath = os.path.join(root, file)
            if replace_in_file(filepath):
                print(f"Updated text in: {filepath}")
                changed_files_count += 1

    print(f"\nTotal files updated with replacements: {changed_files_count}")

if __name__ == "__main__":
    main()
