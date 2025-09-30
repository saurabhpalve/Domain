import sqlite3
import json
from datetime import datetime, timezone
from pathlib import Path
import pandas as pd

DB_PATH = Path.cwd() / "data" / "predictions.db"

def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS predictions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL,
        prediction TEXT NOT NULL,
        url_len INTEGER NOT NULL,
        is_domain_IP INTEGER NOT NULL,
        no_of_sub_domain INTEGER NOT NULL, 
        no_of_obfuscated_chars INTEGER NOT NULL,
        is_https INTEGER NOT NULL,
        no_equal INTEGER NOT NULL,
        no_qmark INTEGER NOT NULL,
        no_amp INTEGER NOT NULL,
        no_dot INTEGER NOT NULL,
        no_underlines INTEGER NOT NULL,
        no_exclamation INTEGER NOT NULL,
        no_tilde INTEGER NOT NULL,
        no_vowels INTEGER NOT NULL,
        has_title INTEGER NOT NULL,
        has_description INTEGER NOT NULL,
        has_external_form_submit INTEGER NOT NULL,
        has_favicon INTEGER NOT NULL,
        no_of_images INTEGER NOT NULL,
        no_of_js INTEGER NOT NULL,
        has_password_field INTEGER NOT NULL,
        has_copyright_info INTEGER NOT NULL,
        has_hidden_field INTEGER NOT NULL,
        no_financial_terms INTEGER NOT NULL,
        has_submit_button INTEGER NOT NULL, 
        timestamp TEXT NOT NULL
    )
    """)
    conn.commit()
    conn.close()

COLUMNS_IN_ORDER = [
        "url_len", "is_domain_IP", "no_of_sub_domain", "no_of_obfuscated_chars",
        "is_https", "no_equal", "no_qmark", "no_amp", "no_dot", "no_underlines",
        "no_exclamation", "no_tilde", "no_vowels", "has_title", "has_description",
        "has_external_form_submit", "has_favicon", "no_of_images", "no_of_js",
        "has_password_field", "has_copyright_info", "has_hidden_field",
        "no_financial_terms", "has_submit_button",
    ]

def log_prediction(url: str, prediction, df: pd.DataFrame) -> None:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    feature_values = [df.iloc[0][col] for col in COLUMNS_IN_ORDER]
    placeholders = ",".join("?" for _ in range(27))
    all_columns = ["url", "prediction"] + COLUMNS_IN_ORDER + ["timestamp"]
    columns_str = ", ".join(f'"{col}"' for col in all_columns)
    values = (url, json.dumps(prediction), *feature_values, datetime.now(timezone.utc).isoformat())
    cursor.execute(f"INSERT INTO predictions ({columns_str}) VALUES ({placeholders})", values)
    conn.commit()
    conn.close()

def get_prediction_by_url(url: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(f"SELECT prediction FROM predictions WHERE url=? ORDER BY id DESC LIMIT 1", (url,))
    result = cursor.fetchone()
    conn.close()

    if result:
        try:
            return json.loads(result[0])
        except Exception:
            return None
    return None


if __name__ == "__main__":
    print(get_prediction_by_url(url="https://www.youtube.com/watch?v=gdNknCDf2LU"))