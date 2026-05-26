from waf.config import FIREBASE_CREDENTIALS_PATH
from waf.db.firebase import FIREBASE_ENABLED, execute_firebase, init_firebase, query_firebase
from waf.db.seed import SEED_RULES
from waf.db.sqlite import execute_sqlite, init_sqlite_tables, query_sqlite


def get_db_connection():
    from waf.db.sqlite import get_connection

    conn = get_connection()
    return conn, "sqlite"


def init_db():
    fb_ok = init_firebase(FIREBASE_CREDENTIALS_PATH)
    if fb_ok:
        print("[INFO] Firebase Firestore initialized successfully")
        return

    init_sqlite_tables()
    _seed_if_empty()


def _seed_if_empty():
    from waf.db.base import execute_db, query_db

    rules_check = query_db("SELECT COUNT(*) as cnt FROM rules", one=True)
    if rules_check and rules_check["cnt"] == 0:
        for r in SEED_RULES:
            execute_db(
                """INSERT INTO rules (rule_id, identifier, pattern, action, category, is_active, blocks_count, severity, description)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",  # noqa: E501
                r,
            )  # noqa: E501
        print("[INFO] Successfully seeded default security profiles into registry.")

        posture_check = query_db("SELECT COUNT(*) as cnt FROM mitigation_state", one=True)
        if posture_check and posture_check.get("cnt", -1) == 0:
            execute_db("INSERT INTO mitigation_state (id, posture) VALUES ('global', 'Standard Posture')")
            print("[INFO] Successfully seeded global posture settings.")


def query_db(query: str, args: tuple = (), one: bool = False):
    if FIREBASE_ENABLED:
        return query_firebase(query, args, one)
    return query_sqlite(query, args, one)


def execute_db(query: str, args: tuple = ()) -> bool:
    if FIREBASE_ENABLED:
        return execute_firebase(query, args)
    return execute_sqlite(query, args)
