// Importing required libraries
const jwt = require("jsonwebtoken");
const CryptoJS = require("crypto-js");

// Secret keys for JWT and AES encryption
const JWT_SECRET = "your_jwt_secret_key"; // Replace with your own secret key
const ENCRYPTION_SECRET = "your_encryption_secret_key"; // Replace with your own encryption secret key

// Function to encrypt the JWT token
const encrypt = (payload) => {
  // Step 1: Create the JWT token
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "1h" });
  console.log("Original JWT:", token);

  // Step 2: Encrypt the JWT token using AES
  const encryptedToken = CryptoJS.AES.encrypt(
    token,
    ENCRYPTION_SECRET
  ).toString();
  console.log("Encrypted JWT:", encryptedToken);

  return encryptedToken;
};

// Function to decrypt the JWT token
const decrypt = (token) => {
  // Step 1: Decrypt the token using AES
  const bytes = CryptoJS.AES.decrypt(token, ENCRYPTION_SECRET);
  const decryptedToken = bytes.toString(CryptoJS.enc.Utf8);
  console.log("Decrypted JWT:", decryptedToken);

  // Step 2: Verify and decode the JWT
  try {
    const decoded = jwt.verify(decryptedToken, JWT_SECRET);
    console.log("Decoded Payload:", decoded);
    return decoded;
  } catch (error) {
    console.error("❌ Token verification failed:", error.message);
    return null;
  }
};

// Testing the encryption and decryption process
(function main() {
  try {
    // Step 1: Create a payload for the token
    const payload = { userId: 123, username: "john_doe" };

    // Step 2: Encrypt the JWT token
    const encryptedToken = encrypt(payload);

    // Step 3: Decrypt the JWT token
    const decodedPayload = decrypt(encryptedToken);

    // Step 4: Check if decoding was successful
    if (decodedPayload) {
      console.log("✅ Success");
    } else {
      console.log("❌ Failed");
    }
  } catch (error) {
    console.error("❌ Error in process:", error.message);
  }
})();

module.exports = {
  encrypt,
  decrypt,
};
