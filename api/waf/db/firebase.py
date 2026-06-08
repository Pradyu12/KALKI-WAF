from datetime import datetime

FIREBASE_ENABLED = False
db = None


def init_firebase(credentials_path: str) -> bool:
    global FIREBASE_ENABLED, db
    try:
        import firebase_admin
        from firebase_admin import credentials, firestore
        from google.auth.exceptions import DefaultCredentialsError

        if credentials_path and __import__("os").path.exists(credentials_path):
            cred = credentials.Certificate(credentials_path)
            firebase_admin.initialize_app(cred)
            db = firestore.client()
            FIREBASE_ENABLED = True
        elif __import__("os").getenv("FIREBASE_PROJECT_ID"):
            cred = credentials.ApplicationDefault()
            firebase_admin.initialize_app(cred)
            db = firestore.client()
            FIREBASE_ENABLED = True
        else:
            FIREBASE_ENABLED = False
            db = None
    except (ImportError, DefaultCredentialsError):
        FIREBASE_ENABLED = False
        db = None
    return FIREBASE_ENABLED


def query_firebase(query: str, args: tuple = (), one: bool = False):
    q = query.strip().lower()
    try:
        if q.startswith("select") and "from rules" in q:
            collection = db.collection("rules")
            docs = collection.stream()
            results = []
            for doc in docs:
                data = doc.to_dict()
                data["rule_id"] = doc.id
                results.append(data)
            return (results[0] if results else None) if one else results

        elif q.startswith("select") and "from security_events" in q:
            collection = db.collection("security_events")
            docs = collection.stream()
            results = []
            for doc in docs:
                data = doc.to_dict()
                data["incident_id"] = doc.id
                results.append(data)
            return (results[0] if results else None) if one else results

        elif q.startswith("select") and "from mitigation_state" in q:
            if "where" in q:
                doc = db.collection("mitigation_state").document("global").get()
                if doc.exists:
                    data = doc.to_dict()
                    data["id"] = "global"
                    return data if one else [data]
                return None if one else []
            else:
                docs = db.collection("mitigation_state").stream()
                results = []
                for doc in docs:
                    data = doc.to_dict()
                    data["id"] = doc.id
                    results.append(data)
                return (results[0] if results else None) if one else results

        return [] if not one else None
    except Exception as e:
        print(f"[FIREBASE ERROR] Query execution failed: {e}")
        return None


def execute_firebase(query: str, args: tuple = ()) -> bool:
    q = query.strip().lower()
    try:
        if q.startswith("insert into rules"):
            rule_id = args[0]
            data = {
                "identifier": args[1],
                "pattern": args[2],
                "action": args[3],
                "category": args[4],
                "is_active": bool(args[5]),
                "blocks_count": int(args[6]),
                "severity": args[7],
                "description": args[8] if len(args) > 8 else "",
            }
            db.collection("rules").document(rule_id).set(data)
            return True

        elif q.startswith("insert into security_events"):
            incident_id = args[0]
            data = {
                "timestamp": args[1]
                if isinstance(args[1], datetime)
                else datetime.fromisoformat(args[1].replace("Z", "+00:00")),  # noqa: E501
                "source_ip": args[2],
                "user_agent": args[3],
                "target_uri": args[4],
                "malicious_payload": args[5],
                "threat_category": args[6],
                "mitigation_action": args[7],
            }
            db.collection("security_events").document(incident_id).set(data)
            return True

        elif q.startswith("update rules set blocks_count"):
            rule_id = args[0] if len(args) == 1 else args[1]
            doc = db.collection("rules").document(rule_id).get()
            if doc.exists:
                data = doc.to_dict()
                data["blocks_count"] = data.get("blocks_count", 0) + 1
                db.collection("rules").document(rule_id).update({"blocks_count": data["blocks_count"]})
                return True
        elif q.startswith("update rules set is_active"):
            rule_id = args[1]
            db.collection("rules").document(rule_id).update({"is_active": bool(args[0])})
            return True

        elif q.startswith("update mitigation_state"):
            db.collection("mitigation_state").document("global").update({"posture": args[0]})
            return True

        elif q.startswith("delete from rules"):
            db.collection("rules").document(args[0]).delete()
            return True

        return False
    except Exception as e:
        print(f"[FIREBASE ERROR] Write transaction failed: {e}")
        return False
