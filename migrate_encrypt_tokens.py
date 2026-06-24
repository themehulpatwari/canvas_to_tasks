"""
One-time migration: encrypt existing plaintext secrets at rest:
  - user_auth.refresh_token  (Google OAuth refresh tokens)
  - user_links.ics_url       (Canvas feed URLs, which embed a bearer token)

The app encrypts these on write (see util.encrypt_token), but rows written
before encryption was enabled remain plaintext. Run this ONCE, after setting
TOKEN_ENC_KEY in the environment, to encrypt those existing rows.

IMPORTANT: run it with the SAME TOKEN_ENC_KEY you set in Heroku / GitHub
Actions. Encrypting with a different key would make the values undecryptable in
production and break the daily sync.

The script is idempotent: already-encrypted rows are detected and skipped, so
it is safe to re-run.

Usage:
    MONGO_URI=... MONGO_DB_NAME=... TOKEN_ENC_KEY=... python migrate_encrypt_tokens.py
    # (or put those in .env)
"""
import os
from dotenv import load_dotenv
from pymongo import MongoClient
from util import encrypt_token, decrypt_token, _get_fernet

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME")


def _is_encrypted(value):
    """True if value already decrypts under the current key (i.e. encrypted)."""
    fernet = _get_fernet()
    if fernet is None or value is None:
        return False
    try:
        fernet.decrypt(value.encode())
        return True
    except Exception:
        return False


def _encrypt_field(collection, field):
    """Encrypt a single string field across every doc in a collection."""
    scanned = encrypted_now = already = skipped = 0
    for doc in collection.find({field: {"$exists": True, "$ne": None}}):
        scanned += 1
        value = doc.get(field)

        if _is_encrypted(value):
            already += 1
            continue

        ciphertext = encrypt_token(value)
        # Safety: never write a value we can't read back to the original.
        if decrypt_token(ciphertext) != value:
            print(f"  ! round-trip check failed for {doc.get('email')!r}; skipping")
            skipped += 1
            continue

        collection.update_one({"_id": doc["_id"]}, {"$set": {field: ciphertext}})
        encrypted_now += 1

    print(
        f"{collection.name}.{field}: scanned={scanned} encrypted_now={encrypted_now} "
        f"already_encrypted={already} skipped={skipped}"
    )


def main():
    if _get_fernet() is None:
        print("TOKEN_ENC_KEY is not set (or invalid). Aborting — nothing to do.")
        return
    if not MONGO_URI or not MONGO_DB_NAME:
        print("MONGO_URI / MONGO_DB_NAME not set. Aborting.")
        return

    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=8000)
    client.admin.command('ping')
    db = client[MONGO_DB_NAME]

    _encrypt_field(db.user_auth, "refresh_token")
    _encrypt_field(db.user_links, "ics_url")


if __name__ == "__main__":
    main()
