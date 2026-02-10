// ----------------------
// Helper functions
// ----------------------
function generateKeyPair() {
  const keyPair = sodium.crypto_box_keypair();
  return {
    publicKey: sodium.to_base64(keyPair.publicKey),
    privateKey: sodium.to_base64(keyPair.privateKey)
  };
}

function saveMyKeys(keys) {
  localStorage.setItem("myKeys", JSON.stringify(keys));
}

function loadMyKeys() {
  const raw = localStorage.getItem("myKeys");
  return raw ? JSON.parse(raw) : null;
}

function loadContacts() {
  return JSON.parse(localStorage.getItem("contacts") || "[]");
}

function saveContacts(contacts) {
  localStorage.setItem("contacts", JSON.stringify(contacts));
}

// ----------------------
// Encryption (to recipient)
// ----------------------
function encryptMessage(recipientPublicKeyBase64, message) {
  const myKeys = loadMyKeys();
  if (!myKeys) throw new Error("No local keypair found");

  const recipientPublicKey = sodium.from_base64(recipientPublicKeyBase64);
  const nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES);

  const cipher = sodium.crypto_box_easy(
    sodium.from_string(message),
    nonce,
    recipientPublicKey,
    sodium.from_base64(myKeys.privateKey)
  );

  return `${myKeys.publicKey}:${sodium.to_base64(nonce)}:${sodium.to_base64(cipher)}`;
}

// ----------------------
// Decryption
// ----------------------
function decryptMessage(encryptedMessage) {
  const myKeys = loadMyKeys();
  if (!myKeys) throw new Error("No local keypair found");

  const parts = encryptedMessage.split(":");
  if (parts.length !== 3) throw new Error("Invalid message format");

  const [senderPublicKeyB64, nonceB64, cipherB64] = parts;
  const senderPublicKey = sodium.from_base64(senderPublicKeyB64);
  const nonce = sodium.from_base64(nonceB64);
  const cipher = sodium.from_base64(cipherB64);

  try {
    const plaintext = sodium.crypto_box_open_easy(
      cipher,
      nonce,
      senderPublicKey,
      sodium.from_base64(myKeys.privateKey)
    );
    return sodium.to_string(plaintext);
  } catch (err) {
    throw new Error("Failed to decrypt message. It may not be intended for you or is corrupted.");
  }
}

// ----------------------
// Copy to clipboard
// ----------------------
function copyToClipboard(text) {
  navigator.clipboard.writeText(text).then(
    () => alert("Copied to clipboard!"),
    () => alert("Failed to copy!")
  );
}

// ----------------------
// Init
// ----------------------
async function init() {
  await sodium.ready;

  // DOM elements
  const myKeyOutput = document.getElementById("myPublicKey");
  const generateBtn = document.getElementById("generateKeys");
  const addContactBtn = document.getElementById("addContact");
  const contactNameInput = document.getElementById("contactName");
  const contactKeyInput = document.getElementById("contactKey");
  const contactList = document.getElementById("contactList");
  const recipientSelect = document.getElementById("recipientSelect");
  const plainText = document.getElementById("plainText");
  const encryptBtn = document.getElementById("encryptBtn");
  const encryptedOutput = document.getElementById("encryptedOutput");
  const encryptedInput = document.getElementById("encryptedInput");
  const decryptBtn = document.getElementById("decryptBtn");
  const decryptedOutput = document.getElementById("decryptedOutput");
  const copyEncryptedBtn = document.getElementById("copyEncryptedBtn");
  const copyDecryptedBtn = document.getElementById("copyDecryptedBtn");

  // ------------------
  // Render functions
  // ------------------
  function renderMyKey() {
    const keys = loadMyKeys();
    myKeyOutput.innerText = keys ? `Your Public Key:\n\n${keys.publicKey}` : "";
  }

  function renderContacts() {
    const contacts = loadContacts();

    contactList.innerHTML = "";
    contacts.forEach((c) => {
      const li = document.createElement("li");
      li.innerText = c.name;
      contactList.appendChild(li);
    });

    recipientSelect.innerHTML = '<option value="">-- Select Recipient --</option>';
    contacts.forEach((c, i) => {
      const option = document.createElement("option");
      option.value = i;
      option.innerText = c.name;
      recipientSelect.appendChild(option);
    });
  }

  // ------------------
  // Button handlers
  // ------------------
  generateBtn.onclick = () => {
    const keys = generateKeyPair();
    saveMyKeys(keys);
    renderMyKey();
  };

  addContactBtn.onclick = () => {
    const name = contactNameInput.value.trim();
    const key = contactKeyInput.value.trim();
    if (!name || !key) return alert("Name and public key are required");

    const contacts = loadContacts();
    contacts.push({ name, publicKey: key });
    saveContacts(contacts);

    contactNameInput.value = "";
    contactKeyInput.value = "";

    renderContacts();
  };

  encryptBtn.onclick = () => {
    const selectedIndex = recipientSelect.value;
    if (selectedIndex === "") return alert("Select a recipient first");

    const contacts = loadContacts();
    const contact = contacts[selectedIndex];
    const message = plainText.value.trim();
    if (!message) return alert("Type a message first");

    try {
      const encrypted = encryptMessage(contact.publicKey, message);
      encryptedOutput.innerText = encrypted;
      copyToClipboard(encrypted); // auto-copy on encrypt
    } catch (err) {
      alert("Encryption failed: " + err.message);
    }
  };

  decryptBtn.onclick = () => {
    const encryptedText = encryptedInput.value.trim();
    if (!encryptedText) return alert("Paste an encrypted message first");

    try {
      const decrypted = decryptMessage(encryptedText);
      decryptedOutput.innerText = decrypted;
      copyToClipboard(decrypted); // auto-copy on decrypt
    } catch (err) {
      decryptedOutput.innerText = err.message;
    }
  };

  copyEncryptedBtn.onclick = () => copyToClipboard(encryptedOutput.innerText);
  copyDecryptedBtn.onclick = () => copyToClipboard(decryptedOutput.innerText);

  // ------------------
  // Initial render
  // ------------------
  renderMyKey();
  renderContacts();
}

// ----------------------
// Run
// ----------------------
init();
