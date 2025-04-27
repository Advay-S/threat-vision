import requests
from fluvio import Fluvio
import json
import time
from dotenv import load_dotenv
import os

class API_Fetcher:
    def __init__(self):
        self.OTXKey = os.getenv("OTX_API_KEY")  # Ensure the key is valid for testing.
        if not self.OTXKey:
            raise ValueError("OTX_API_KEY is not set in the .env file.")

    def fetchOTX(self):
        url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
        headers = {"X-OTX-API-KEY": self.OTXKey}
        try:
            response = requests.get(url, headers=headers)
            print("OTX Status Code:", response.status_code)
            if response.status_code == 200:
                return json.dumps(response.json())
            else:
                return json.dumps({"error": f"OTX API failed with status code {response.status_code}", "details": response.text})
        except Exception as e:
            return json.dumps({"error": f"OTX API error: {str(e)}"})


class FluvioProducer:
    def __init__(self):
        try:
            self.fluvio = Fluvio.connect("local")  # Replace with your actual Fluvio profile name
            print("Successfully connected to Fluvio.")
        except Exception as e:
            print(f"Fluvio connection failed: {str(e)}")
            self.fluvio = None  # Set to None to indicate no valid connection

    def send_to_topic(self, topic, message):
        if not self.fluvio:
            print("No Fluvio connection established. Skipping message sending.")
            return
        try:
            producer = self.fluvio.topic_producer(topic)
            if message:
                key = "default-key".encode("utf-8")  # Encoding key to bytes (necessary for Fluvio)
                message_bytes = message.encode("utf-8")  # Encoding message to bytes
                producer.send(key, message_bytes)
                print(f"📤 Sent data to topic '{topic}' with key '{key.decode('utf-8')}'")
            else:
                print(f" No valid message to send for topic '{topic}'")
        except Exception as e:
            print(f"Failed to send to topic '{topic}': {str(e)}")


def main():
    fetcher = API_Fetcher()
    producer = FluvioProducer()

    while True:
        try:
            print("\n🚀 Fetching data...")

            # Fetch OTX data
            otx_data = fetcher.fetchOTX()

            print(f"📗 Sample OTX Data: {otx_data[:200]}")  # Preview first 200 characters of fetched data

            # Send to Fluvio topic
            producer.send_to_topic("otx-blue", otx_data)

            print("⏱️ Waiting 60 seconds before next fetch...")
            time.sleep(60)
        except Exception as e:
            print(f"Error in main loop: {str(e)}")
            print("⏱️ Retrying in 60 seconds...")

if __name__ == "__main__":
    main()
