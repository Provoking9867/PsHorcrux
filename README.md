# PsHorcrux
Attempt to implement a Shamir's Secret Sharing script in PowerShell


1. System Architecture & Prerequisites
This system utilizes an implementation of Shamir's Secret Sharing natively written in PowerShell, cryptographically locked to the standard 0x11D Galois Field polynomial. This ensures 100% mathematical cross-compatibility with the Linux ssss-split and ssss-combine utilities.
  •	Working Directory: All operations, dependencies, and temporary files strictly execute within %HOMEDRIVE%%HOMEPATH%\horcrux.
  •	Integrity Lock: The script will not execute unless a .sha256 hash file matches the script's exact physical state, preventing malicious tampering.
  •	Dependencies: Requires OpenSSL to be installed and accessible in the system PATH. ZXing.Net is dynamically downloaded to the working directory for QR code processing.

2. Workflow I: Creating a Vault
    1.	Click 1. CREATE VAULT and select a target folder containing the files you wish to protect.
    2.	Enter a 2-digit Hexadecimal Vault ID (e.g., A1 or 7F).
    3.	Define your total number of shards (n) and the threshold required to unlock them (k).
    4.	A Diceware generator will appear. Roll 5 physical dice (or simulate them) to select 5 words from the EFF Large Wordlist. This becomes your AES-256 encryption passkey.
    5.	The system compresses your files, encrypts the ZIP via OpenSSL using your passkey, generates a file hash manifest, and mathematically splits the passkey into n unique shards.
    6.	The resulting shards are saved as both raw .txt strings and scannable .png QR codes inside individual subfolders.

3. Workflow II: Recovering a Key
The Recovery Room utilizes strict validation to guarantee mathematical integrity before attempting reconstruction.
  1.	Click 2. RECOVER KEY and declare your threshold (k). The UI will generate exactly k empty fields. You cannot submit more or fewer shards than this number.
  2.	Method A (Digital Files): Click Add Files and select your .txt or .png shards. The system will automatically decode the QR images and sequentially drop the valid text strings into the empty fields.
  3.	Method B (Physical QR Scanning): * Click Webcam Scanner.
    o	The native Windows Camera app will launch.
    o	Hold your physical QR shard to the lens. Click the decoded text overlay to copy it to your clipboard.
    o	Return to the Horcrux window, click an empty Shard field, and paste.
    o	Press the Tab key to jump to the next empty field and repeat until all boxes are filled.

4.	Click JOIN. The engine runs a strict validation check:
  o	Blocks empty fields.
  o	Blocks illegal characters, spaces, and binary artifacts.
  o	Prevents literal shard duplication (pasting the same string twice).
  o	Prevents index duplication (submitting two different shards that share the same ID number).

5.	Upon successful validation, the GF(2^8) engine mathematically reconstructs and displays your original Diceware passkey. The Windows Camera app is automatically terminated.

4. Workflow III: Decrypting the Payload
  1.	With the recovered key populated in the main window, click 3. DECRYPT PAYLOAD.
  2.	Select the Vault_[ID].enc file.
  3.	The system decrypts the payload, extracts the files to an Unlocked directory, and sequentially cross-references every file against the Vault_Manifest.txt.
  4.	If a single byte of any file has been altered since the vault was created, a Tamper Alert will trigger.

5. Workflow IV: Secure Shredder
  •	Select a target folder to permanently destroy its contents.
  •	The shredder executes a Department of Defense (DoD 5220.22-M) compliant 3-pass wipe, writing random cryptographic bytes over the physical disk sectors before deleting the file pointer.
  •	Performs a bottom-up directory sweep to safely remove all nested subfolders.

