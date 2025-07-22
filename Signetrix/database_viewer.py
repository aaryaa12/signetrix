#!/usr/bin/env python3
"""
Signetrix - PKI System Database Viewer

A professional GUI tool to view, export, and inspect SQLite database contents for the Signetrix PKI system.
"""

import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
import json
from datetime import datetime
from typing import Any, List, Optional

# =====================
# Database Viewer Class
# =====================

class DatabaseViewer:
    """
    Provides a GUI for browsing, exporting, and inspecting the Signetrix database.
    """
    def __init__(self, db_path: str = "pki_system.db") -> None:
        """
        Initialize the database viewer and set up the UI.
        :param db_path: Path to the SQLite database file.
        """
        self.db_path = db_path
        self.root = tk.Tk()
        self.setup_ui()
    
    def setup_ui(self) -> None:
        """
        Set up the database viewer UI (window, controls, treeview, status bar).
        """
        self.root.title("Signetrix - Database Viewer")
        self.root.geometry("1200x800")
        self.root.configure(bg='#f0f0f0')
        # Main frame
        main_frame = tk.Frame(self.root, bg='#f0f0f0')
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        # Title
        title_label = tk.Label(main_frame, text="\U0001F5C4 Signetrix Database Viewer",
                              font=('Arial', 16, 'bold'), bg='#f0f0f0')
        title_label.pack(pady=(0, 20))
        # Table selection frame
        table_frame = tk.Frame(main_frame, bg='#f0f0f0')
        table_frame.pack(fill='x', pady=(0, 10))
        tk.Label(table_frame, text="Select Table:", font=('Arial', 12, 'bold'), bg='#f0f0f0').pack(side='left')
        self.table_var = tk.StringVar(value="users")
        table_combo = ttk.Combobox(table_frame, textvariable=self.table_var,
                                  values=["users", "certificates", "signed_documents", "verification_logs", "audit_log"],
                                  state="readonly", width=20)
        table_combo.pack(side='left', padx=10)
        table_combo.bind('<<ComboboxSelected>>', self.on_table_change)
        # Refresh button
        refresh_btn = tk.Button(table_frame, text="\U0001F504 Refresh", command=self.refresh_data,
                               bg='#3498db', fg='white', font=('Arial', 10, 'bold'), padx=15)
        refresh_btn.pack(side='left', padx=10)
        # Export button
        export_btn = tk.Button(table_frame, text="\U0001F4CA Export", command=self.export_data,
                              bg='#27ae60', fg='white', font=('Arial', 10, 'bold'), padx=15)
        export_btn.pack(side='left', padx=5)
        # Create treeview with scrollbars
        tree_frame = tk.Frame(main_frame)
        tree_frame.pack(fill='both', expand=True)
        self.tree = ttk.Treeview(tree_frame)
        self.tree.pack(side='left', fill='both', expand=True)
        v_scrollbar = ttk.Scrollbar(tree_frame, orient='vertical', command=self.tree.yview)
        v_scrollbar.pack(side='right', fill='y')
        self.tree.configure(yscrollcommand=v_scrollbar.set)
        h_scrollbar = ttk.Scrollbar(main_frame, orient='horizontal', command=self.tree.xview)
        h_scrollbar.pack(fill='x')
        self.tree.configure(xscrollcommand=h_scrollbar.set)
        # Status bar
        self.status_label = tk.Label(main_frame, text="Ready", bg='#34495e', fg='white',
                                    font=('Arial', 10), anchor='w', padx=10)
        self.status_label.pack(fill='x', pady=(10, 0))
        # Load initial data
        self.refresh_data()
    
    def on_table_change(self, event: Optional[tk.Event] = None) -> None:
        """
        Handle table selection change and refresh data.
        """
        self.refresh_data()
    
    def refresh_data(self) -> None:
        """
        Refresh the data display for the selected table.
        """
        try:
            table_name = self.table_var.get()
            self.status_label.config(text=f"Loading {table_name} data...")
            self.root.update()
            # Clear existing data
            for item in self.tree.get_children():
                self.tree.delete(item)
            # Connect to database
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                # Get table info
                cursor.execute(f"PRAGMA table_info({table_name})")
                columns_info = cursor.fetchall()
                columns = [col[1] for col in columns_info]
                # Configure treeview columns
                self.tree['columns'] = columns
                self.tree['show'] = 'headings'
                for col in columns:
                    self.tree.heading(col, text=col.title())
                    self.tree.column(col, width=120, minwidth=80)
                # Get data
                cursor.execute(f"SELECT * FROM {table_name}")
                rows = cursor.fetchall()
                for row in rows:
                    formatted_row = []
                    for item in row:
                        if item is None:
                            formatted_row.append("NULL")
                        elif isinstance(item, str) and len(item) > 50:
                            formatted_row.append(item[:47] + "...")
                        else:
                            formatted_row.append(str(item))
                    self.tree.insert('', 'end', values=formatted_row)
                self.status_label.config(text=f"Loaded {len(rows)} records from {table_name}")
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Error loading data: {str(e)}")
            self.status_label.config(text=f"Error loading {table_name}")
        except Exception as e:
            messagebox.showerror("Error", f"Unexpected error: {str(e)}")
            self.status_label.config(text="Error occurred")
    
    def export_data(self) -> None:
        """
        Export current table data to a text file.
        """
        try:
            table_name = self.table_var.get()
            filename = f"pki_{table_name}_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(f"SELECT * FROM {table_name}")
                rows = cursor.fetchall()
                cursor.execute(f"PRAGMA table_info({table_name})")
                columns_info = cursor.fetchall()
                columns = [col[1] for col in columns_info]
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(f"Signetrix - {table_name.title()} Table Export\n")
                    f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("=" * 80 + "\n\n")
                    f.write(" | ".join(f"{col:15}" for col in columns) + "\n")
                    f.write("-" * (len(columns) * 18) + "\n")
                    for row in rows:
                        formatted_row = []
                        for item in row:
                            if item is None:
                                formatted_row.append("NULL".ljust(15))
                            else:
                                str_item = str(item)
                                if len(str_item) > 15:
                                    str_item = str_item[:12] + "..."
                                formatted_row.append(str_item.ljust(15))
                        f.write(" | ".join(formatted_row) + "\n")
                    f.write(f"\nTotal Records: {len(rows)}\n")
            messagebox.showinfo("Export Successful", f"Data exported to: {filename}")
            self.status_label.config(text=f"Exported {len(rows)} records to {filename}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export data: {str(e)}")
    
    def run(self) -> None:
        """
        Run the database viewer main loop.
        """
        self.root.mainloop()

# =====================
# Application Entry Point
# =====================

def main() -> None:
    """
    Main function for the Signetrix database viewer.
    """
    print("Signetrix Database Viewer")
    print("=" * 30)
    try:
        viewer = DatabaseViewer()
        viewer.run()
    except Exception as e:
        print(f"Error starting database viewer: {e}")
        input("Press Enter to exit...")

if __name__ == "__main__":
    main()
