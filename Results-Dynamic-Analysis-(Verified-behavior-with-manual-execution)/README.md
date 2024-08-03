# Dynamic Analysis (Verified behavior with manual execution)

This project demonstrates the manual execution of Visual Studio Code (VS Code) extensions, logs the extensions' actions, captures network requests using the [mitmproxy tool](https://mitmproxy.org/), and checks for suspicious extensions. Each sheet corresponds to a result section in the paper, found in the Results section "Suspicious Extensions."

When replicating these experiments, you need to [download the extensions](https://drive.google.com/drive/u/4/folders/1faRAX9sdzxGsrUx_dOpXsFpqdMkvzg1n) using Extension Id (e.g., f2fd462f-f1bd-4c62-b54f-59a4e5ffc6a3) and run them through instrumented VS Code.

## Column Descriptions

Each column in the Excel sheet represents the following:

- **Id**: Unique extension ID we created to search extensions
- **Extension Name**: Extension's name
- **Usage**: VS Code marketplace page description or basic functionality
- **Download Counts**: Download count at the VS Code marketplace page
- **Comment**: Suspicious behavior of the extension
- **Transparency**: Whether they describe the actual behavior in the VS Code marketplace page
- **Flow/Logs**: mitmproxy log file (Flow), and the logs captured when executing VS Code extensions locally
- **Sharing Reason**: Purpose of the code sharing (Only in the Code Sharing sheet)
- **Tracking Data**: Types of data used for tracking (Only in the Tracking sheet)

## Sample Code

To demonstrate code sharing, we have used the following sample JavaScript code file, which you might find in the flow files:

```javascript
const forge = require("node-forge");
const fs = require("fs");

// Generate a key pair (public and private keys)
const keys = forge.pki.rsa.generateKeyPair({ bits: 2048 });

// Convert the keys to PEM format (for demonstration purposes)
const privateKeyPem = forge.pki.privateKeyToPem(keys.privateKey);
const publicKeyPem = forge.pki.publicKeyToPem(keys.publicKey);

// Save the keys to files (in practice, keep these keys secure)
fs.writeFileSync("private_key.pem", privateKeyPem, "utf8");
fs.writeFileSync("public_key.pem", publicKeyPem, "utf8");
console.log("Keys generated and saved.");

// Function to sign a message
function signMessage(privateKey, message) {
  const md = forge.md.sha256.create();
  md.update(message, "utf8");
  const signature = privateKey.sign(md);
  return signature;
}

// Function to verify a signature
function verifySignature(publicKey, message, signature) {
  const md = forge.md.sha256.create();
  md.update(message, "utf8");
  return publicKey.verify(md.digest().getBytes(), signature);
}

const message = "This is a signed message";

// Sign the message using the private key
const privateKey = forge.pki.privateKeyFromPem(
  fs.readFileSync("private_key.pem", "utf8")
);
const signature = signMessage(privateKey, message);

console.log("Message:", message);
console.log("Signature:", signature);

// Verify the signature using the public key
const publicKey = forge.pki.publicKeyFromPem(
  fs.readFileSync("public_key.pem", "utf8")
);
const isSignatureValid = verifySignature(publicKey, message, signature);

if (isSignatureValid) {
  console.log("Signature is valid.");
} else {
  console.log("Signature is not valid.");
}
```
