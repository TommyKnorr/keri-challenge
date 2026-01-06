# KERI Programming Challenge

This repository contains a minimal Falcon-based HTTP service implemented using
**KERI (Key Event Receipt Infrastructure)** and a corresponding pytest test
fixture. The implementation demonstrates correct use of KERI identifiers,
SAIDs, CESR-formatted HTTP signature headers, and signature verification for
both requests and responses.

The service and tests are intentionally local-only and in-process. No external
network calls are made.

---

## Overview

### Server behavior
- **POST /**  
  Registers a JSON SAD (Self-Addressing Data) containing:
  - `d` – SAID (self-addressing identifier)
  - `i` – Requestor AID
  - `n` – Name

  The request must include an HTTP `Signature` header:
  - Indexed signature (index `0`)
  - Signed over the SAID (`d`)
  - Generated using the requestor’s AID private key

  The response:
  - Returns the same JSON SAD
  - Includes a `Signature` header signed by the host AID over the response SAID

- **GET /**  
  Retrieves a previously registered record using **exactly one** query
  parameter:
  - `name=`
  - `AID=`
  - `SAID=`

  The request `Signature` header:
  - Is signed by the requestor AID
  - Covers a KERI `Diger` over the query string

  The response:
  - Returns the matching JSON SAD
  - Includes a host-signed `Signature` header

### Storage
- Data is stored in **module-level in-memory dictionaries**
- A public `reset_storage()` function is provided for test isolation
- No persistence beyond test execution is performed

---

## Requirements

### Python
- **Recommended:** Python **3.12**
- **Tested locally:** Python **3.13.6**

The application logic is Python-version agnostic.  
However, KERI depends on native cryptographic libraries (`pysodium` /
`libsodium`), which currently have the most reliable wheel support on Python
3.12. Python 3.13 works when those dependencies are available (as in local
development).

### Dependencies
See [`requirements.txt`](requirements.txt).

---

## Installation

The following steps apply to **Windows, macOS, and Linux**.

### 1. Clone the repository
```bash
git clone https://github.com/TommyKnorr/keri-challenge.git <local-repo>
cd <local-repo>
```

### 2. Create and activate a virtual environment

#### Windows (PowerShell)
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

#### macOS / Linux
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

---

## Running Tests

All functionality is validated through pytest.

From the repository root:
```bash
python -m pytest
```

### Notes
- Tests use Falcon’s in-process test client (no sockets, no ports)
- Temporary directories are created under `.tmp/` via `pytest.ini`
- Storage is reset automatically between tests
- The test suite validates:
  - Successful POST + GET flows
  - Signature verification
  - Failure on invalid signatures

---

## Project Structure

```
.
├── server.py
├── test_server.py
├── requirements.txt
├── pytest.ini
├── README.md
└── .gitignore
```

---

## Platform Notes

### Windows
- Uses project-local temp directories to avoid `%TEMP%` permission issues
- Tested on Windows with Python 3.13.6

### macOS
- Fully supported
- Uses pytest-managed temp directories (no SIP issues)

### Linux
- Fully supported
- Verified locally on Debian 13.2
- Recommended Python version: **3.12**

---

## Design Notes

- Only **indexed signatures** are used (single index `0`)
- CESR formatting is handled via `keri.end.ending.signature`
- Signature parsing uses `ending.designature`
- Query digests are generated using `keri.core.coring.Diger`
- Code style and naming align closely with keripy examples (e.g. `test_ending.py`)

---

## License / Usage

This repository is provided as a programming challenge submission and reference
implementation. No warranty is implied.
