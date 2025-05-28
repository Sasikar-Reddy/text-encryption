async function deriveKey(password, salt) {
    const encoder = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        encoder.encode(password),
        "PBKDF2",
        false,
        ["deriveKey"]
    );
    return window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

async function encryptText() {
    const inputText = document.getElementById("inputText").value;
    const password = document.getElementById("password").value;
    const encoder = new TextEncoder();
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    const iv = window.crypto.getRandomValues(new Uint8Array(12));

    const key = await deriveKey(password, salt);

    const encryptedData = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        encoder.encode(inputText)
    );

    const cipherText = new Uint8Array(encryptedData);
    const output = {
        cipherText: arrayBufferToHex(cipherText),
        iv: arrayBufferToHex(iv),
        salt: arrayBufferToHex(salt)
    };

    document.getElementById("outputText").value = JSON.stringify(output);
}

async function decryptText() {
    const encryptedData = JSON.parse(document.getElementById("outputText").value);
    const password = document.getElementById("password").value;

    const key = await deriveKey(password, hexToArrayBuffer(encryptedData.salt));

    const decryptedData = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: hexToArrayBuffer(encryptedData.iv) },
        key,
        hexToArrayBuffer(encryptedData.cipherText)
    );

    const decoder = new TextDecoder();
    document.getElementById("outputText").value = decoder.decode(decryptedData);
}

function arrayBufferToHex(buffer) {
    return Array.from(new Uint8Array(buffer))
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join('');
}

function hexToArrayBuffer(hex) {
    const buffer = new ArrayBuffer(hex.length / 2);
    const view = new Uint8Array(buffer);
    for (let i = 0; i < hex.length; i += 2) {
        view[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return buffer;
}
