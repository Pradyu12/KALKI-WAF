import argparse
import httpx
import sys
import json
from typing import Optional

BASE_URL = "http://127.0.0.1:8000"

def get_status():
    try:
        response = httpx.get(f"{BASE_URL}/api/v1/threat-intel/alerts")
        response.raise_for_status()
        data = response.json()
        metrics = data.get("metrics", {})
        print("\n--- KALKI WAF STATUS ---")
        print(f"Posture:        {metrics.get('posture')}")
        print(f"Total Ingress:  {metrics.get('total_ingress')}")
        print(f"Total Blocked:  {metrics.get('total_blocked')}")
        print(f"Active Rules:   {metrics.get('active_rules_count')}")
        print(f"Upstream URL:   {metrics.get('upstream_url')}")
        print("------------------------\n")
    except Exception as e:
        print(f"Error fetching status: {e}")

def list_rules():
    try:
        response = httpx.get(f"{BASE_URL}/api/v1/rules")
        response.raise_for_status()
        rules = response.json()
        print("\n--- KALKI WAF RULES ---")
        print(f"{'ID':<15} {'Identifier':<30} {'Active':<10} {'Blocks':<10}")
        for rule in rules:
            active = "Yes" if rule.get("is_active") else "No"
            print(f"{rule.get('rule_id'):<15} {rule.get('identifier'):<30} {active:<10} {rule.get('blocks_count'):<10}")
        print("------------------------\n")
    except Exception as e:
        print(f"Error listing rules: {e}")

def toggle_rule(rule_id: str, enable: bool):
    try:
        response = httpx.put(
            f"{BASE_URL}/api/v1/rules/{rule_id}/toggle",
            json={"is_active": enable}
        )
        response.raise_for_status()
        state = "enabled" if enable else "disabled"
        print(f"Rule {rule_id} successfully {state}.")
    except Exception as e:
        print(f"Error toggling rule {rule_id}: {e}")

def set_posture(posture: str):
    valid_postures = ["Monitor Only", "Standard Posture", "Under Attack"]
    if posture not in valid_postures:
        print(f"Invalid posture. Choose from: {', '.join(valid_postures)}")
        return
    try:
        response = httpx.post(
            f"{BASE_URL}/api/v1/mitigation-posture",
            json={"posture": posture}
        )
        response.raise_for_status()
        print(f"Mitigation posture updated to: {posture}")
    except Exception as e:
        print(f"Error updating posture: {e}")

def show_logs(limit: int = 10):
    try:
        response = httpx.get(f"{BASE_URL}/api/v1/threat-intel/alerts")
        response.raise_for_status()
        data = response.json()
        incidents = data.get("incidents", [])[:limit]
        print(f"\n--- RECENT INCIDENTS (Last {len(incidents)}) ---")
        print(f"{'Time':<20} {'IP':<15} {'Category':<15} {'Action':<10} {'URI'}")
        for inc in incidents:
            print(f"{inc.get('timestamp'):<20} {inc.get('source_ip'):<15} {inc.get('threat_category'):<15} {inc.get('mitigation_action'):<10} {inc.get('target_uri')}")
        print("------------------------\n")
    except Exception as e:
        print(f"Error fetching logs: {e}")

def delete_rule(rule_id: str):
    try:
        response = httpx.delete(f"{BASE_URL}/api/v1/rules/{rule_id}")
        response.raise_for_status()
        print(f"Rule {rule_id} successfully deleted.")
    except Exception as e:
        # Try to extract error detail if possible
        detail = e.response.json().get("detail") if hasattr(e, "response") and e.response else str(e)
        print(f"Error deleting rule {rule_id}: {detail}")

def main():
    parser = argparse.ArgumentParser(description="KALKI WAF CLI Tool")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Status command
    subparsers.add_parser("status", help="Display current WAF metrics and posture")

    # Logs command
    logs_parser = subparsers.add_parser("logs", help="Show recent security incidents")
    logs_parser.add_argument("-n", "--limit", type=int, default=10, help="Number of incidents to show (default 10)")

    # Rules command
    rules_parser = subparsers.add_parser("rules", help="Manage security rules")
    rules_subparsers = rules_parser.add_subparsers(dest="subcommand", help="Rule operations")

    rules_subparsers.add_parser("list", help="List all security rules")

    toggle_parser = rules_subparsers.add_parser("toggle", help="Enable or disable a specific rule")
    toggle_parser.add_argument("rule_id", help="The ID of the rule to toggle")
    toggle_parser.add_argument("--off", action="store_true", help="Disable the rule (default is enable)")

    delete_parser = rules_subparsers.add_parser("delete", help="Delete a custom security rule")
    delete_parser.add_argument("rule_id", help="The ID of the rule to delete")

    # Posture command
    posture_parser = subparsers.add_parser("posture", help="Set the global mitigation posture")
    posture_parser.add_argument("name", choices=["Monitor Only", "Standard Posture", "Under Attack"],
                               help="The posture name")

    args = parser.parse_args()

    if args.command == "status":
        get_status()
    elif args.command == "logs":
        show_logs(args.limit)
    elif args.command == "rules":
        if args.subcommand == "list":
            list_rules()
        elif args.subcommand == "toggle":
            toggle_rule(args.rule_id, not args.off)
        elif args.subcommand == "delete":
            delete_rule(args.rule_id)
        else:
            rules_parser.print_help()
    elif args.command == "posture":
        set_posture(args.name)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
