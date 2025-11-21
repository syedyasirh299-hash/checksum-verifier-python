# Checksum Verifier

A professional desktop application for computing and verifying file checksums to ensure file integrity and authenticity. Perfect for verifying downloads, detecting file tampering, and maintaining data integrity.

## Features

- **Multiple Hash Algorithms**: Support for MD5, SHA1, and SHA256
- **Simple GUI Interface**: Easy-to-use Tkinter-based interface
- **File Integrity Verification**: Compare computed hashes with expected values
- **Automatic Logging**: Saves all operations in both JSON and CSV formats
- **Clipboard Integration**: One-click copy of computed hashes
- **Large File Support**: Efficient chunk-based processing for files of any size
- **Real-time Comparison**: Instant visual feedback (✓ MATCH / ✗ MISMATCH)
- **Detailed Audit Trail**: Timestamps and results for all verification operations

## Use Cases

- Verify downloaded software integrity
- Detect file tampering or corruption
- Validate backup files
- Ensure secure file transfers
- Compliance and audit requirements

## Technologies Used

- Python 3
- Tkinter (GUI)
- hashlib (Cryptographic hashing)
- JSON & CSV (Data logging)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/checksum-verifier.git
cd checksum-verifier
```

2. No additional dependencies required (uses Python standard library only!)

## Usage

1. Run the application:
```bash
python checksum_verifier.py
```

2. Click "Browse" to select a file
3. Choose hashing algorithm (MD5, SHA1, or SHA256)
4. Click "Compute Hash"
5. (Optional) Paste expected hash to compare
6. Click "Compare" to verify integrity

## Output Files

All operations are logged in the `logs/` directory:
- `checksum_log.json` - JSON format logs
- `checksum_log.csv` - CSV format logs

## Log Entry Format
```json
{
  "time": "2025-11-21T10:30:00Z",
  "file": "/path/to/file.zip",
  "algorithm": "sha256",
  "computed_hash": "abc123...",
  "expected_hash": "abc123...",
  "match": true
}
```

## Screenshots

*(Add screenshots of your application here)*

## Security Note

This tool is designed for file verification purposes. Always obtain expected hash values from official, trusted sources.

## Supported Hash Algorithms

- **MD5**: Fast but not recommended for security-critical applications
- **SHA1**: Better than MD5 but consider using SHA256
- **SHA256**: Recommended for modern security requirements

## Requirements

- Python 3.6 or higher
- No external dependencies

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
```

## **File Naming Suggestions:**

- Main file: `checksum_verifier.py` or `file_integrity_checker.py`
- Alternative: `hash_verifier.py`

## **Project Structure:**
```
checksum-verifier/
├── checksum_verifier.py
├── README.md
├── LICENSE
├── .gitignore
└── logs/
    ├── checksum_log.json
    └── checksum_log.csv
```

## **.gitignore Content:**
```
# Logs
logs/
*.log

# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python

# Virtual Environment
venv/
env/

# IDE
.vscode/
.idea/
