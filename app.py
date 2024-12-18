import requests
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

def fetch_and_save_to_db(api_url, db_file, table_name, total_records):
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        # Update schema to include CVSS score
        cursor.execute(f"""
            CREATE TABLE IF NOT EXISTS {table_name} (
                cve_id TEXT PRIMARY KEY,
                description TEXT,
                cvss_score REAL
            )
        """)
        
        results_per_page = 200
        for start_index in range(0, total_records, results_per_page):
            params = {
                "resultsPerPage": results_per_page,
                "startIndex": start_index
            }
            response = requests.get(api_url, params=params)
            response.raise_for_status()
            data = response.json()
            if "vulnerabilities" not in data:
                print(f"No vulnerabilities data found in response for startIndex {start_index}")
                break
            for record in data["vulnerabilities"]:
                cve = record.get("cve", {})
                cve_id = cve.get("id", "N/A").strip()
                descriptions = cve.get("descriptions", [])
                description = descriptions[0].get("value", "N/A").strip() if descriptions else "N/A"
                
                # Extract CVSS score
                metrics = record.get("metrics", {})
                cvss_metric = metrics.get("cvssMetricV2", [])
                cvss_score = cvss_metric[0].get("cvssData", {}).get("baseScore") if cvss_metric else None

                # Avoid duplicate entries
                cursor.execute(f"SELECT 1 FROM {table_name} WHERE cve_id = ?", (cve_id,))
                if cursor.fetchone():
                    continue 
                
                # Insert data into the database
                cursor.execute(f"""
                    INSERT INTO {table_name} (cve_id, description, cvss_score)
                    VALUES (?, ?, ?)
                """, (cve_id, description, cvss_score))
        
        conn.commit()
        conn.close()
        print(f"Data saved successfully to database '{db_file}' in table '{table_name}'")
    except requests.exceptions.RequestException as e:
        print(f"Error fetching data: {e}")
    except sqlite3.Error as e:
        print(f"Database error: {e}")

@app.route('/api/cves', methods=['GET'])
def get_cves():
    db_file = "cve_data.db"
    table_name = "cve_vulnerabilities"
    cve_id = request.args.get('cve_id')
    year = request.args.get('year')
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        query = f"SELECT cve_id, description, cvss_score FROM {table_name} WHERE 1=1"
        params = []
        if cve_id:
            query += " AND cve_id = ?"
            params.append(cve_id)
        if year:
            query += " AND cve_id LIKE ?"
            params.append(f"CVE-{year}-%")
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        return jsonify([{"cve_id": row[0], "description": row[1], "cvss_score": row[2]} for row in rows])
    except sqlite3.Error as e:
        return jsonify({"error": f"Database error: {e}"}), 500

if __name__ == "__main__":
    api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    db_file = "cve_data.db"
    table_name = "cve_vulnerabilities"
    total_records = 1000
    fetch_and_save_to_db(api_url, db_file, table_name, total_records)
    app.run(debug=True)
