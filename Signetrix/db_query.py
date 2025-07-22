#!/usr/bin/env python3
"""
Signetrix - PKI System Database Query Tool

A professional command-line tool for quick, safe, and flexible database queries and statistics.
"""

import sqlite3
import sys
import json
from datetime import datetime
from typing import Any, List, Optional, Tuple

# =====================
# Database Query Class
# =====================

class DatabaseQuery:
    """
    Provides methods for querying the Signetrix database for tables, schemas, statistics, and activity.
    """
    def __init__(self, db_path: str = "pki_system.db") -> None:
        """
        Initialize the query tool with the given database path.
        :param db_path: Path to the SQLite database file.
        """
        self.db_path = db_path
        
    def execute_query(self, query: str) -> Any:
        """
        Execute a SQL query and return results or status message.
        :param query: SQL query string.
        :return: Query result or status string.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(query)
                if query.strip().upper().startswith('SELECT'):
                    return cursor.fetchall()
                else:
                    conn.commit()
                    return f"Query executed successfully. Rows affected: {cursor.rowcount}"
        except sqlite3.Error as e:
            return f"Database error: {str(e)}"
        except Exception as e:
            return f"Error: {str(e)}"
    
    def show_tables(self) -> List[Tuple[str]]:
        """
        Show all tables in the database.
        :return: List of table names.
        """
        query = "SELECT name FROM sqlite_master WHERE type='table';"
        return self.execute_query(query)
    
    def show_table_schema(self, table_name: str) -> List[Tuple[Any, ...]]:
        """
        Show schema for a specific table.
        :param table_name: Name of the table.
        :return: List of schema rows.
        """
        query = f"PRAGMA table_info({table_name});"
        return self.execute_query(query)
    
    def quick_stats(self) -> dict:
        """
        Show quick database statistics (user, document, verification, audit counts).
        :return: Dictionary of statistics.
        """
        stats = {}
        result = self.execute_query("SELECT COUNT(*) FROM users")
        stats['Total Users'] = result[0][0] if result else 0
        result = self.execute_query("SELECT COUNT(*) FROM signed_documents")
        stats['Signed Documents'] = result[0][0] if result else 0
        result = self.execute_query("SELECT COUNT(*) FROM verification_logs")
        stats['Verifications'] = result[0][0] if result else 0
        result = self.execute_query("SELECT COUNT(*) FROM audit_log")
        stats['Audit Entries'] = result[0][0] if result else 0
        return stats
    
    def recent_activity(self, limit: int = 10) -> List[Tuple[Any, ...]]:
        """
        Show recent system activity from the audit log.
        :param limit: Number of entries to return.
        :return: List of activity rows.
        """
        query = f"""
        SELECT u.username, a.action, a.details, a.timestamp
        FROM audit_log a
        LEFT JOIN users u ON a.user_id = u.id
        ORDER BY a.timestamp DESC
        LIMIT {limit}
        """
        return self.execute_query(query)

# =====================
# Utility Functions
# =====================

def print_table(data: Optional[List[Tuple[Any, ...]]], headers: Optional[List[str]] = None) -> None:
    """
    Print data in a formatted table.
    :param data: List of row tuples.
    :param headers: Optional list of column headers.
    """
    if not data:
        print("No data found.")
        return
    if headers:
        print(" | ".join(f"{h:15}" for h in headers))
        print("-" * (len(headers) * 18))
    for row in data:
        formatted_row = []
        for item in row:
            if item is None:
                formatted_row.append("NULL".ljust(15))
            else:
                str_item = str(item)
                if len(str_item) > 15:
                    str_item = str_item[:12] + "..."
                formatted_row.append(str_item.ljust(15))
        print(" | ".join(formatted_row))

# =====================
# Main CLI Entry Point
# =====================

def main() -> None:
    """
    Main function for the Signetrix database query tool.
    Provides both command-line and interactive modes.
    """
    print("\U0001F5C4 PKI System Database Query Tool")
    print("=" * 40)
    db = DatabaseQuery()
    if len(sys.argv) > 1:
        # Command line query
        query = " ".join(sys.argv[1:])
        print(f"Executing: {query}")
        print("-" * 40)
        result = db.execute_query(query)
        if isinstance(result, list):
            print_table(result)
        else:
            print(result)
        return
    # Interactive mode
    print("Available commands:")
    print("1. tables - Show all tables")
    print("2. schema <table> - Show table schema")
    print("3. stats - Show quick statistics")
    print("4. activity - Show recent activity")
    print("5. users - Show all users")
    print("6. docs - Show signed documents")
    print("7. verify - Show verification logs")
    print("8. audit - Show audit log")
    print("9. query <SQL> - Execute custom SQL")
    print("10. quit - Exit")
    print()
    while True:
        try:
            command = input("db> ").strip().lower()
            if command == "quit" or command == "exit":
                break
            elif command == "tables":
                result = db.show_tables()
                print("Tables:")
                for table in result:
                    print(f"  - {table[0]}")
            elif command.startswith("schema "):
                table_name = command.split()[1]
                result = db.show_table_schema(table_name)
                print(f"Schema for {table_name}:")
                print_table(result, ["ID", "Name", "Type", "NotNull", "Default", "PK"])
            elif command == "stats":
                stats = db.quick_stats()
                print("Database Statistics:")
                for key, value in stats.items():
                    print(f"  {key}: {value}")
            elif command == "activity":
                result = db.recent_activity()
                print("Recent Activity:")
                print_table(result, ["User", "Action", "Details", "Timestamp"])
            elif command == "users":
                result = db.execute_query("SELECT id, username, created_at, last_login, is_active FROM users")
                print("Users:")
                print_table(result, ["ID", "Username", "Created", "Last Login", "Active"])
            elif command == "docs":
                result = db.execute_query("SELECT id, user_id, document_name, signed_at, verification_count FROM signed_documents")
                print("Signed Documents:")
                print_table(result, ["ID", "User ID", "Document", "Signed At", "Verifications"])
            elif command == "verify":
                result = db.execute_query("SELECT id, document_id, verification_result, verified_at FROM verification_logs ORDER BY verified_at DESC LIMIT 20")
                print("Recent Verifications:")
                print_table(result, ["ID", "Doc ID", "Result", "Verified At"])
            elif command == "audit":
                result = db.execute_query("SELECT id, user_id, action, timestamp FROM audit_log ORDER BY timestamp DESC LIMIT 20")
                print("Recent Audit Log:")
                print_table(result, ["ID", "User ID", "Action", "Timestamp"])
            elif command.startswith("query "):
                sql = command[6:]  # Remove "query " prefix
                result = db.execute_query(sql)
                if isinstance(result, list):
                    print_table(result)
                else:
                    print(result)
            elif command == "help":
                print("Available commands: tables, schema <table>, stats, activity, users, docs, verify, audit, query <SQL>, quit")
            else:
                print("Unknown command. Type 'help' for available commands.")
        except KeyboardInterrupt:
            print("\nGoodbye!")
            break
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    main()
