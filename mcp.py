import psutil
import time
import logging
from datetime import datetime
import sqlite3
import os
from flask import Flask, jsonify
import threading

class MCP:
    def __init__(self):
        self.app = Flask(__name__)
        self.setup_logging()
        self.setup_routes()
        self.monitoring = True
        self.db_path = os.path.join('instance', 'factory_checklist.db')
        
    def setup_logging(self):
        logging.basicConfig(
            filename='mcp.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        
    def setup_routes(self):
        @self.app.route('/mcp/status')
        def get_status():
            return jsonify(self.get_system_status())
            
        @self.app.route('/mcp/db/health')
        def get_db_health():
            return jsonify(self.check_db_health())
            
        @self.app.route('/mcp/system/stats')
        def get_system_stats():
            return jsonify(self.get_system_stats())
            
    def get_system_status(self):
        return {
            'status': 'operational',
            'timestamp': datetime.now().isoformat(),
            'cpu_usage': psutil.cpu_percent(),
            'memory_usage': psutil.virtual_memory().percent,
            'disk_usage': psutil.disk_usage('/').percent
        }
        
    def check_db_health(self):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = cursor.fetchall()
            
            # Check for any errors
            cursor.execute("PRAGMA integrity_check")
            integrity = cursor.fetchone()[0]
            
            conn.close()
            
            return {
                'status': 'healthy' if integrity == 'ok' else 'unhealthy',
                'tables': [table[0] for table in tables],
                'integrity_check': integrity
            }
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }
            
    def get_system_stats(self):
        return {
            'cpu': {
                'usage': psutil.cpu_percent(),
                'cores': psutil.cpu_count(),
                'frequency': psutil.cpu_freq().current
            },
            'memory': {
                'total': psutil.virtual_memory().total,
                'available': psutil.virtual_memory().available,
                'used': psutil.virtual_memory().used,
                'percent': psutil.virtual_memory().percent
            },
            'disk': {
                'total': psutil.disk_usage('/').total,
                'used': psutil.disk_usage('/').used,
                'free': psutil.disk_usage('/').free,
                'percent': psutil.disk_usage('/').percent
            }
        }
        
    def monitor_system(self):
        while self.monitoring:
            status = self.get_system_status()
            logging.info(f"System Status: {status}")
            
            # Check for critical conditions
            if status['cpu_usage'] > 90:
                logging.warning("High CPU usage detected!")
            if status['memory_usage'] > 90:
                logging.warning("High memory usage detected!")
            if status['disk_usage'] > 90:
                logging.warning("High disk usage detected!")
                
            time.sleep(60)  # Check every minute
            
    def start(self):
        # Start monitoring in a separate thread
        monitor_thread = threading.Thread(target=self.monitor_system)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        # Start the Flask server
        self.app.run(host='0.0.0.0', port=5001)
        
    def stop(self):
        self.monitoring = False

if __name__ == "__main__":
    mcp = MCP()
    try:
        mcp.start()
    except KeyboardInterrupt:
        mcp.stop() 