import sqlite3
from datetime import datetime

def check_database():
    """Check the database structure and content."""
    print(f"\nChecking database at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 50 + "\n")
    
    try:
        conn = sqlite3.connect('factory.db')
        cursor = conn.cursor()
        
        # Get all tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        
        print("Tables in database:")
        for table in tables:
            print(f"- {table[0]}")
            
            # Get table schema
            cursor.execute(f"PRAGMA table_info({table[0]})")
            columns = cursor.fetchall()
            print("\nColumns:")
            for col in columns:
                print(f"  - {col[1]} ({col[2]})")
            
            # Get row count
            cursor.execute(f"SELECT COUNT(*) FROM {table[0]}")
            count = cursor.fetchone()[0]
            print(f"\nTotal rows: {count}\n")
            
            # Show sample data if available
            if count > 0:
                cursor.execute(f"SELECT * FROM {table[0]} LIMIT 3")
                rows = cursor.fetchall()
                print("Sample data:")
                for row in rows:
                    print(f"  {row}")
            print("-" * 50 + "\n")
            
    except sqlite3.Error as e:
        print(f"Database error occurred: {str(e)}")
    finally:
        if 'conn' in locals():
            conn.close()

if __name__ == '__main__':
    check_database() 