
import os
from dotenv import load_dotenv
from google import genai

load_dotenv()

api_key = os.getenv("GEMINI_API_KEY")
assert api_key, "ERROR: GEMINI_API_KEY not found. Check your .env file!"

client = genai.Client()

response = client.models.generate_content(
    model="gemini-3.5-flash-lite",
    contents="Reply with the exact phrase: 'Telemetry online.'"
)

print(response.text)
