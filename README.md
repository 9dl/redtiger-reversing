# Reverse Engineering the RedTiger Stealer (skiddy ahh stealer)
## Overview
In this walkthrough, we'll analyze a Python-compiled stealers using common reverse engineering tools. Always perform this analysis in a isolated VM environment.

## Tools Used
- PyInstxtractor
- Pylingual decompiler
- Python cryptography libraries
- cURL

## Step 1: Extracting the Python Bytecode
1. Download [pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor)
2. Execute with:
   ```bash
   python pyinstxtractor.py RedTigerStealer.exe
   ```
3. Locate the extracted `.pyc` file in the created directory (typically `main.pyc`)

## Step 2: Decompiling to Source Code
1. Use [Pylingual](https://www.pylingual.io) to decompile the .pyc file
2. Search for cryptographic functions - in this case, we found:
   ```python
   def Decrypt(QNMDHUMNTJQMXQYXOXWFIRSGCDRGQNDLVXYEUHFNFAZCCLSZMDGYEPJ, v4r_key):
       # [implementation details]
   ```

## Step 3: Analyzing the Cryptography
The stealer uses AES-256-CBC with PBKDF2 key derivation. Here's the reconstructed decryption routine:

```python
import base64
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def Decrypt(encrypted_data_b64, password):
    # Key derivation function
    def DeriveKey(password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode() if isinstance(password, str) else password)

    # Decryption process
    encrypted_data = base64.b64decode(encrypted_data_b64)
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    
    key = DeriveKey(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Handle padding
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    
    return (unpadder.update(decrypted_padded) + unpadder.finalize()).decode()
```

## Step 4: Extracting the Webhook
1. Locate the encrypted configuration:
   ```python
   encrypted_webhook = '\nLfMKTGpBnaXnEVp6RZ7Yb1VQmAPsUC+YKgE00fzwVP6ZqXlVBm5pIMympdh+GBWOklOnfgFt4+m4zXXpO0+cMtnEmIl2s9JnYSONQd698pAq3QHHoRjtbQHmVYpmSXTw0vCzutEM5RGt8pqT5rttRd+p8HNC5SfJCB32VAHP0uoSlXDSeY3ow9SrEWy2F/NhLi73Ud6E7ccRYST0k3YFdg==\n'
   encryption_key = 'uDsVlYqrhZRgdRVBvklMUoSffRbjqVzEfGXCzBthdZnsknEIvhjYWpyOJxXncsCKVeLXzGGbhUOkTMcWUgoUYyxBoxDhowBGTJKqEHimpJuAqnq'
   ```

2. Execute the decryption:
   ```python
   print(Decrypt(encrypted_webhook.strip(), encryption_key))
   ```

This will output the Discord webhook URL used by the stealer.

## Step 5: Neutralizing the Webhook
**Important:** Only perform this if you have legitimate access to the webhook

```bash
curl -s -o nul -w "Initial Check: %{http_code}\n" https://discord.com/api/webhooks/1357441309891362916/sdYwCO1pUPP4tSfi30k_SNkZKGXVrYIKlvgKw4MOmrb5tXHytUWlrZcMiABBa0dDpnqV && curl -s -X DELETE https://discord.com/api/webhooks/XXXXXXXXXXXXXXXXXX > nul && curl -s -o nul -w "Post-Delete Check: %{http_code}\n" https://discord.com/api/webhooks/XXXXXXXXXXXXXXXXXX
```

## Indicators of Compromise
- Webhook URL: `https://discord.com/api/webhooks/XXXXXXXXXXXXXXXXXXXXXXXXXXX`
