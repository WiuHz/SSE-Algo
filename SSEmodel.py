import hashlib
import hmac
import json
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class SearchableSymmetricEncryption:

    def __init__(self):
        self.k_enc = AESGCM.generate_key(bit_length=256)
        self.k_trap = os.urandom(32)

        self.cipher = AESGCM(self.k_enc)

    def _prf_trapdoor(self, keyword: str) -> str:
        return hmac.new(
            self.k_trap, keyword.encode("utf-8"), hashlib.sha256
        ).hexdigest()

    def build_index_and_encrypt(self, raw_logs: list):
        encrypted_dataset = {}
        secure_index = {}  

        for log in raw_logs:
            log_id = log["log_id"]

            log_bytes = json.dumps(log).encode("utf-8")

            nonce = os.urandom(12)
            ciphertext = self.cipher.encrypt(nonce, log_bytes, None)
            encrypted_dataset[log_id] = {
                "nonce": nonce,
                "ciphertext": ciphertext,
            }

            keywords = [
                log["user_id"],
                log["ip"],
                log["accessed_file"],
                f"suspicious_{log['is_suspicious']}",
            ]

            for kw in keywords:
                trapdoor_label = self._prf_trapdoor(kw)
                if trapdoor_label not in secure_index:
                    secure_index[trapdoor_label] = []
                if log_id not in secure_index[trapdoor_label]:
                    secure_index[trapdoor_label].append(log_id)

        return secure_index, encrypted_dataset

    def generate_trapdoor(self, keyword: str) -> str:
        return self._prf_trapdoor(keyword)

    def server_search(self, secure_index: dict, trapdoor: str) -> list:
        return secure_index.get(trapdoor, [])

    def decrypt_log(self, encrypted_record: dict) -> dict:
        nonce = encrypted_record["nonce"]
        ciphertext = encrypted_record["ciphertext"]
        decrypted_bytes = self.cipher.decrypt(nonce, ciphertext, None)
        return json.loads(decrypted_bytes.decode("utf-8"))


if __name__ == "__main__":


    RAW_FORENSIC_LOGS = [
        {
            "log_id": 101,
            "user_id": "emp_01",
            "ip": "10.0.0.15",
            "accessed_file": "PAYROLL.pdf",
            "is_suspicious": 1,
        },
        {
            "log_id": 102,
            "user_id": "emp_02",
            "ip": "10.0.0.18",
            "accessed_file": "REPORT.pdf",
            "is_suspicious": 0,
        },
        {
            "log_id": 103,
            "user_id": "emp_03",
            "ip": "10.0.0.22",
            "accessed_file": "PAYROLL.pdf",
            "is_suspicious": 1,
        },
        {
            "log_id": 104,
            "user_id": "emp_01",
            "ip": "10.0.0.15",
            "accessed_file": "SYSTEM.config",
            "is_suspicious": 1,
        },
        {
            "log_id": 105,
            "user_id": "emp_05",
            "ip": "10.0.0.44",
            "accessed_file": "LOGINS.db",
            "is_suspicious": 0,
        },
    ]

    sse = SearchableSymmetricEncryption()

    print(
        "[1] Building Secure Inverted Index and encrypting forensic log dataset..."
    )
    secure_index, encrypted_db = sse.build_index_and_encrypt(
        RAW_FORENSIC_LOGS
    )
    print(
        f"    -> Offloaded {len(encrypted_db)} ciphertexts and Secure Index to Cloud Server.\n"
    )

    search_keyword = "10.0.0.15"
    print(
        f"[2] Investigator initiating query for evidence keyword: '{search_keyword}'"
    )

    trapdoor_token = sse.generate_trapdoor(search_keyword)
    print(
        f"    -> Generated Search Trapdoor (HMAC Token): {trapdoor_token}\n"
    )

    matched_ids = sse.server_search(secure_index, trapdoor_token)
    print("[3] Cloud Server executing search query over Secure Index...")
    print(f"    -> Matched Record IDs: {matched_ids}")
    print(
        "    (*) Security Guarantee: Server CANNOT read log payloads and DOES NOT KNOW the keyword is '10.0.0.15'!\n"
    )

    print(
        "[4] Investigator retrieves matched ciphertexts and decrypts contents locally:"
    )
    for log_id in matched_ids:
        raw_record = sse.decrypt_log(encrypted_db[log_id])
        print(
            f"    • [Log ID {log_id}]: User={raw_record['user_id']} | IP={raw_record['ip']} | File={raw_record['accessed_file']}"
        )