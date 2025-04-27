import json
import pymysql
from datetime import datetime
from fluvio import Fluvio, Offset

def main():
    # Connect to Fluvio
    fluvio = Fluvio.connect()
    consumer = fluvio.partition_consumer("enriched-records", 0)
    stream = consumer.stream(Offset.beginning())

    # Connect to MySQL
    connection = pymysql.connect(
        host='localhost',
        user='threatuser',
        password='root',
        database='threat_vision',
        charset='utf8mb4',
        cursorclass=pymysql.cursors.DictCursor
    )

    try:
        with connection.cursor() as cursor:
            for record in stream:
                try:
                    # Parse the JSON record
                    data = json.loads(record.value_string())

                    # Extract fields
                    attack_types = data.get('attack_types', [])
                    attack_vectors = data.get('attack_vectors', [])
                    urgency = data.get('urgency', ['', ''])
                    targets = data.get('targets', [])
                    locations = data.get('locations', [])
                    expiration_date_str = data.get('expiration_date', '')

                    # Convert ISO 8601 datetime string to MySQL DATETIME format
                    if expiration_date_str.strip() == "":
                        expiration_date = None  # Or set a default value like '1970-01-01 00:00:00'
                    else:
                        try:
                            dt_object = datetime.fromisoformat(expiration_date_str)
                            expiration_date = dt_object.strftime('%Y-%m-%d %H:%M:%S')
                        except ValueError:
                            print(f"Invalid date format: {expiration_date_str}")
                            continue  # Skip this record if date format is invalid

                    # Insert a single record into the database with JSON arrays
                    sql = """
                        INSERT INTO enriched_records (
                            attack_types,
                            attack_vectors,
                            urgency,
                            targets,
                            locations,
                            expiration_date
                        ) VALUES (%s, %s, %s, %s, %s, %s)
                    """
                    cursor.execute(sql, (
                        json.dumps(attack_types),  # Convert list to JSON
                        json.dumps(attack_vectors),  # Convert list to JSON
                        json.dumps(urgency),  # Convert list to JSON
                        json.dumps(targets),  # Convert list to JSON
                        json.dumps(locations),  # Convert list to JSON
                        expiration_date  # Can be None
                    ))
                    connection.commit()
                    print(f"Inserted record with expiration date: {expiration_date}")
                except Exception as e:
                    print(f"Error processing record: {e}")
                    connection.rollback()
    finally:
        connection.close()

if __name__ == "__main__":
    main()