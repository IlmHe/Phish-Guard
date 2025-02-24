# Phish-Guard

Phish-Guard is a privacy-friendly, lightweight browser extension designed to detect phishing URLs, and other malicious content. It operates seamlessly in the background, providing users with an easy-to-use tool to enhance their online security.

## Features

- Detects phishing emails and URLs
- Lightweight and efficient
- Privacy-friendly: no data collection
- Easy to use and out of the way for end users

## Installation

### Prerequisites

- [Node.js](https://nodejs.org/) (version 22.14.0)
- [npm](https://www.npmjs.com/) (version 10.9.2)
- [web-ext](https://www.npmjs.com/package/web-ext) (install globally)

### Steps

1. Clone the repository:

    ```bash
    git clone https://github.com/IlmHe/Phish-Guard.git
    cd Phish-Guard
    ```

2. Install dependencies:

    ```bash
    npm install
    ```

3. Build the project:

    ```bash
    npm run build
    ```

4. Start the development server with hot reload:

    ```bash
    npm start
    ```

5. The extension will automatically load in a testing browser.

## Usage
Phish-Guard runs when the user manually initiates a scan. To use the extension, right-click on the text or link you want to check and select the Phish-Guard option from the context menu. You can view the extension's logs by opening the browser's developer tools and navigating to the background page's console.

## Contributing

We welcome contributions from the community! Here are some ways you can help:

### Reporting Bugs

If you encounter any issues or bugs, please report them using [GitHub Issues](https://github.com/IlmHe/Phish-Guard/issues). When reporting a bug, please include:

- A clear and descriptive title
- Steps to reproduce the issue
- Expected and actual results
- Any relevant screenshots or logs

### Feature Requests

If you have an idea for a new feature or an improvement, please open a [GitHub Issue](https://github.com/IlmHe/Phish-Guard/issues) and describe your suggestion in detail.

### Submitting Pull Requests

1. Fork the repository.
2. Create a new branch for your feature or bugfix:

    ```bash
    git checkout -b feature/your-feature-name
    ```

3. Make your changes and commit them with a clear and descriptive commit message.
4. Push your changes to your forked repository:

    ```bash
    git push origin feature/your-feature-name
    ```

5. Open a pull request on the main repository and provide a detailed description of your changes.

## License

Phish-Guard is licensed under the GNU Affero General Public License.
