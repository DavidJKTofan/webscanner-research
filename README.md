# WebScanner Research

WebScanner is a tool built using Cloudflare Workers that allows you to perform website scanning and gather information about a domain. This tool provides insights into DNS records, HTTP response information, and basic security header analysis for the specified domain.

## Features

- Resolve DNS records including A, MX, and TXT records.
- Fetch HTTP information such as status code, status text, and headers.
- Analyze basic security headers to identify potential security vulnerabilities.

## Usage

Access the WebScanner by making a GET request to the deployed worker's URL with the `domain` query parameter:

   ```
   https://webscanner-research.cf-testing.workers.dev/?domain=example.com
   ```

## Contributing

Contributions are welcome! If you find a bug or have an idea for an enhancement, please open an issue or submit a pull request.

## License

This project is licensed under the [MIT License](LICENSE).