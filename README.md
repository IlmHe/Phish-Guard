# Phish-Guard

Phish-Guard is a lightweight browser extension designed to help users identify potentially malicious URLs by checking them against a known phishing database and providing quick links for further investigation.

## Current Features

*   **Context Menu Integration:** Right-click on links or selected text to initiate a scan.
*   **URL Confirmation:** Presents the identified URL in a popup for confirmation before scanning.
*   **Database Check:** Verifies the URL against a user-managed Supabase database of known phishing sites.
*   **Status Indication:** Clearly indicates if the URL was found in the database or not.
*   **VirusTotal Integration:** Provides a direct link to check the URL's domain on VirusTotal.
*   **Site File Access:** Offers quick links to attempt viewing the site's `robots.txt` and to search for its sitemap (`sitemap.xml` or `sitemap.txt`) via Google.

## Installation & Running

### Prerequisites

*   [Node.js](https://nodejs.org/) (LTS version recommended)
*   [npm](https://www.npmjs.com/) (comes with Node.js)
*   Supabase Project: You need a Supabase project with a table (e.g., `phish-co-za_urls`) containing a `url` column for known phishing sites.

### Setup

1.  Clone the repository:
    ```bash
    git clone https://github.com/IlmHe/Phish-Guard.git
    cd Phish-Guard
    ```

2.  Create a `.env` file in the `Phish-Guard` directory with your Supabase credentials:
    ```dotenv
    SUPABASE_URL="YOUR_SUPABASE_URL"
    SUPABASE_KEY="YOUR_SUPABASE_ANON_KEY"
    ```
    *(Replace `YOUR_SUPABASE_URL` and `YOUR_SUPABASE_ANON_KEY` with your actual Supabase project URL and anon key.)*

3.  Install dependencies:
    ```bash
    npm install
    ```

### Development

To run the extension in a development environment with automatic reloading:

```bash
npm start
```

This command uses `web-ext` to run the extension in a temporary browser profile (usually Firefox). It watches for file changes and rebuilds/reloads the extension automatically. Your `.env` file will be used during the build process.

### Production Build

To create a distributable version of the extension (e.g., for manual installation or publishing):

```bash
npm run build
```

This will create the necessary bundled files in the `dist` directory. You can then load this `dist` directory as an unpacked extension in your browser (Chrome, Firefox, Edge, etc.).

## Usage

1.  While browsing, right-click on a link, selected text containing a URL, or anywhere on a page (to scan the page's URL).
2.  Select "Scan with Phish-Guard" from the context menu.
3.  A popup window will appear showing the detected URL and domain.
4.  Click "Scan" to check the URL against the Supabase database and get links for VirusTotal, `robots.txt`, and sitemap search.
5.  The results will indicate if the URL was found in the database and provide the relevant links.
6.  Click "Close" or "Cancel" to dismiss the popup.

## Future Plans

*   **Integration with Additional Databases/APIs:** Explore integrating checks against other public threat intelligence feeds or phishing databases (e.g., PhishTank, OpenPhish, Google Safe Browsing API - subject to API terms and availability) to provide more comprehensive results.
*   **URL Analysis:** Implement basic client-side analysis of URL structure for common phishing patterns (e.g., excessive subdomains, misleading characters).
*   **Configuration Options:** Allow users to configure API keys or select which databases to query via an options page.
*   **Improved UI/UX:** Enhance the visual feedback and user flow within the popup.

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

Phish-Guard is licensed under the GNU Affero General Public License.
