import re

def strip_ansi(text):
    # Regex to strip ANSI escape sequences
    ansi_escape = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)

def main():
    with open('agy_dropdown_capture.bin', 'rb') as f:
        data = f.read()
    
    # Try to decode as utf-8, ignoring errors
    decoded = data.decode('utf-8', errors='ignore')
    
    # Print stripped text
    stripped = strip_ansi(decoded)
    print("=== STRIPPED TEXT ===")
    print(stripped)
    print("=====================")
    
    # Also save it to a file
    with open('scratch/capture_text.txt', 'w') as f_out:
        f_out.write(stripped)

if __name__ == '__main__':
    main()
