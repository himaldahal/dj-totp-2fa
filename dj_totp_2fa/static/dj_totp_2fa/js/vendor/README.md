# Vendored libraries

`qrcode.min.js` is [qrcode-generator](https://www.npmjs.com/package/qrcode-generator) 2.0.4 by Kazuhiko Arase (MIT
licence, see `LICENSE-qrcode-generator.txt`). It was downloaded once from the npm registry (`dist/qrcode.js`) and
minified with terser (`terser dist/qrcode.js -c -m`). It is served from this package's own static files; nothing is
ever loaded from a CDN at runtime. It draws the setup QR code in the browser, so the secret never leaves the page.

To update: `npm pack qrcode-generator`, minify `dist/qrcode.js`, prepend the one-line banner and replace the file.
