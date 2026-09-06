# Async OpenAPI Security Scanner

A fast, modular Python scanner for detecting OpenAPI security header and CORS misconfigurations.

## Requirements

* Python 3.8+
* `httpx`
* `pytest`

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/fabian-saad/async-openapi-scanner.git
cd async-openapi-scanner
```

### 2. Install dependencies

```bash
pip install httpx pytest
```

## Usage

Run the scanner directly from the command line:

```bash
python main.py --spec https://petstore.swagger.io/v2/swagger.json --base-url https://petstore.swagger.io/v2 --output report.json
```

### Command Line Arguments

| Argument     | Description                                                | Default                                       |
| ------------ |------------------------------------------------------------| --------------------------------------------- |
| `--spec`     | URL or local path to an OpenAPI/Swagger JSON specification | `https://petstore.swagger.io/v2/swagger.json` |
| `--base-url` | Base URL of the target API                                 | `https://petstore.swagger.io/v2`              |
| `--output`   | Output filename for the JSON report                        | `report.json`                                 |

## Output Example

```json
{
  "target": "https://petstore.swagger.io/v2",
  "timestamp": "2026-09-06T23:57:13.093793",
  "scanned_count": 20,
  "results": [
    {
      "endpoint": "/pet/findByStatus",
      "method": "GET",
      "status_code": 200,
      "cors": {
        "vulnerable": true,
        "details": "Wildcard '*' Origin allowed"
      },
      "headers": {
        "score": "0/7",
        "details": {
          "Strict-Transport-Security": false,
          "Content-Security-Policy": false,
          "X-Frame-Options": false,
          "X-Content-Type-Options": false,
          "Referrer-Policy": false,
          "Permissions-Policy": false,
          "X-XSS-Protection": false
        }
      }
    }
  ]
}
```

## Running Tests

Execute the unit test suite using `pytest`:

```bash
pytest
```

## License

Distributed under the MIT License. See [`LICENSE`](LICENSE) for more information.
