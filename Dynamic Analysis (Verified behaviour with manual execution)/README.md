# Dynamic Analysis (Verified behaviour with manual execution)

This project demonstrates the manual execution of Visual Studio Code (VS Code) extensions, logs the extensions' actions, captures network requests using the mitmproxy tool (https://mitmproxy.org/), and checks for suspicious extensions. Each sheet corresponds to a result section in the paper, which can be found in the Results section "Suspicious Extensions."

## Instructions

When replicating these experiments, you need to download the extensions (https://drive.google.com/drive/folders/1pVXDiTUhqvoPx3ZrfjOGM0NmUc4pByTD) using Extension Id (ex: f2fd462f-f1bd-4c62-b54f-59a4e5ffc6a3) and run them through custom VS Code.

## Column Descriptions

Each column in the sheet represents the following:

- **Id**: Unique extension Id we created to search extensions
- **Extension Name**: Extension's name
- **Usage**: VS Code marketplace page description or basic functionality
- **Download Counts**: Download count at the VS Code marketplace page
- **Comment**: Suspicious behavior of the extension
- **Transparency**: Whether they describe the actual behavior in the VS Code marketplace page
- **Flow/Logs**: mitmproxy log file (Flow), and the logs captured when executing VS Code extensions locally.

## Additional Columns in Code Sharing

- **Sharing Reason**: Purpose of the code sharing

To demonstrate code sharing, we have used the following sample code file, which you might find in the flow files:

"const forge = require('node-forge');\r\nconst fs = require('fs');\r\n\r\n// Generate a key pair (public and private keys)\r\nconst keys = forge.pki.rsa.generateKeyPair({ bits: 2048 });\r\n\r\n// Convert the keys to PEM format (for demonstration purposes)\r\nconst privateKeyPem = forge.pki.privateKeyToPem(keys.privateKey);\r\nconst publicKeyPem = forge.pki.publicKeyToPem(keys.publicKey);\r\n\r\n// Save the keys to files (in practice, keep these keys secure)\r\nfs.writeFileSync('private_key.pem', privateKeyPem, 'utf8');\r\nfs.writeFileSync('public_key.pem', publicKeyPem, 'utf8');\r\nconsole.log('Keys generated and saved.');\r\n\r\n// Function to sign a message\r\nfunction signMessage(privateKey, message) {\r\n const md = forge.md.sha256.create();\r\n md.update(message, 'utf8');\r\n const signature = privateKey.sign(md);\r\n return signature;\r\n}\r\n\r\n// Function to verify a signature\r\nfunction verifySignature(publicKey, message, signature) {\r\n const md = forge.md.sha256.create();\r\n md.update(message, 'utf8');\r\n return publicKey.verify(md.digest().getBytes(), signature);\r\n}\r\n\r\nconst message = 'This is a signed message';\r\n\r\n// Sign the message using the private key\r\nconst privateKey = forge.pki.privateKeyFromPem(fs.readFileSync('private_key.pem', 'utf8'));\r\nconst signature = signMessage(privateKey, message);\r\n\r\nconsole.log('Message:', message);\r\nconsole.log('Signature:', signature);\r\n\r\n// Verify the signature using the public key\r\nconst publicKey = forge.pki.publicKeyFromPem(fs.readFileSync('public_key.pem', 'utf8'));\r\nconst isSignatureValid = verifySignature(publicKey, message, signature);\r\n\r\nif (isSignatureValid) {\r\n console.log('Signature is valid.');\r\n} else {\r\n console.log('Signature is not valid.');\r\n}\r\n\r\n"

## Additional Column in Tracking

- **Tracking Data**: Types of data used for tracking
