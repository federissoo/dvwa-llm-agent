"""
agent/dvwa_client.py — HTTP client for DVWA interaction.

Owns a requests.Session so the PHPSESSID cookie is managed automatically.
No global mutable state — all session data lives inside the client instance.
"""

import re
import time

import requests

_DB_ERRORS = ["sql syntax", "mysqli_error", "sqlite3 exception", "database error"]


class DVWAClient:
    def __init__(self, base_url: str = "http://127.0.0.1:4280"):
        self.base_url = base_url
        self.sqli_url = f"{base_url}/vulnerabilities/sqli/"
        self.session = requests.Session()
        self.session.cookies.set("security", "low")

    def login(self) -> bool:
        login_url = f"{self.base_url}/login.php"
        print("[LOGIN] Autenticazione in corso su DVWA (admin/password)...")
        try:
            res = self.session.get(login_url, timeout=15)
            token = self._extract_csrf_token(res.text)

            data = {"username": "admin", "password": "password", "Login": "Login"}
            if token:
                data["user_token"] = token

            res2 = self.session.post(login_url, data=data, timeout=15)
            if "login.php" not in res2.url:
                print("[LOGIN] Autenticato con successo.")
                return True
            print("[LOGIN] Autenticazione fallita: reindirizzato a login.php.")
            return False
        except Exception as e:
            print(f"❌ [LOGIN] Errore durante l'autenticazione: {e}")
            return False

    def reset_database(self) -> bool:
        setup_url = f"{self.base_url}/setup.php"
        print("\n[RESET DATABASE] Ripristino del database DVWA...")
        try:
            res = self.session.get(setup_url, timeout=15)
            token = self._extract_csrf_token(res.text)

            data = {"create_db": "Create / Reset Database"}
            if token:
                data["user_token"] = token

            self.session.post(setup_url, data=data, timeout=5)
            time.sleep(3)

            if self.login():
                print("[RESET DATABASE] Sessione autenticata aggiornata.")
                return True

            print("[RESET DATABASE] Reset completato ma login fallito.")
            return False
        except Exception as e:
            print(f"❌ [RESET DATABASE] Errore durante il reset del database: {e}")
            return False

    def execute_sqli(self, payload: str) -> dict:
        params = {"id": payload, "Submit": "Submit"}
        print(f"\n[HTTP] GET {self.sqli_url} | id={payload}")

        try:
            res = self.session.get(self.sqli_url, params=params, timeout=15)

            if "login.php" in res.url:
                print("[HTTP] Sessione scaduta — reindirizzato a login.php")
                return {
                    "risposta_http_raw": "SESSIONE SCADUTA: reindirizzato a login.php",
                    "attacco_successo": False,
                    "sessione_scaduta": True,
                }

            first_names = res.text.count("First name:")
            testo_pulito = " ".join(re.sub("<.*?>", " ", res.text).split())

            if first_names >= 2:
                print(f"[HTTP] SUCCESSO — trovati {first_names} record 'First name:'")
                return {
                    "risposta_http_raw": testo_pulito[:2000],
                    "attacco_successo": True,
                    "sessione_scaduta": False,
                }

            print(f"❌ [HTTP] FALLITO — solo {first_names} record 'First name:'")
            return {
                "risposta_http_raw": testo_pulito[:2000],
                "attacco_successo": False,
                "sessione_scaduta": False,
            }

        except requests.exceptions.ConnectionError as exc:
            return {
                "risposta_http_raw": f"ERRORE DI CONNESSIONE: {exc}",
                "attacco_successo": False,
                "sessione_scaduta": False,
            }
        except Exception as exc:
            return {
                "risposta_http_raw": f"ERRORE INATTESO: {exc}",
                "attacco_successo": False,
                "sessione_scaduta": False,
            }

    def run_regression_tests(self) -> tuple[bool, str]:
        test_cases = [
            ("1", "First name: admin", "Query legittima id=1"),
            ("2", "First name:", "Query legittima id=2"),
            ("999", None, "ID inesistente id=999"),
        ]

        for test_id, expected, description in test_cases:
            try:
                res = self.session.get(
                    self.sqli_url,
                    params={"id": test_id, "Submit": "Submit"},
                    timeout=15,
                )

                if "login.php" in res.url:
                    return False, f"{description}: sessione scaduta"

                res_lower = res.text.lower()
                for err in _DB_ERRORS:
                    if err in res_lower:
                        return False, f"{description}: errore database rilevato ({err})"

                if expected and expected not in res.text:
                    return (
                        False,
                        f"{description}: risposta attesa '{expected}' non trovata",
                    )

            except Exception as e:
                return False, f"{description}: eccezione {e}"

        return True, ""

    @staticmethod
    def _extract_csrf_token(html: str) -> str | None:
        match = re.search(
            r"name=['\"]user_token['\"]\s+value=['\"]([a-f0-9]+)['\"]", html
        )
        return match.group(1) if match else None
