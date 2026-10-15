from enum import Enum
from dotenv import load_dotenv
from pydantic import BaseModel, Field
from google import genai
from google.genai import types

load_dotenv()
client = genai.Client()

class SeverityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

# TODO: Add the missing fields to LogAnalysis with clear Field(description="...") hints:
# - severity: SeverityLevel
# - error_code: int
# - is_compromised: bool
# - recommended_fix: list[str]
class LogAnalysis(BaseModel):
    severity: SeverityLevel = Field(description="Classified incident severity")
    error_code: int = Field(description="HTTP or system error code, or -1 if unavailable")
    is_compromised: bool = Field(description="Indicates whether unauthorized access succeeded")
    recommended_fix: list[str] = Field(description="List of recommended remediation actions")
    summary: str = Field(description="Concise one-sentence technical incident summary")

# TODO: Improve this system prompt so the model accurately classifies SIEM logs
SYSTEM_PROMPT = """
You are a cybersecurity log analyst.
Analyze the server log and identify its severity, error code, and whether the system is compromised.
Provide a short summary and recommended fixes.
"""

def parse_server_log(raw_log: str) -> LogAnalysis:
    response = client.models.generate_content(
        model="gemini-3.5-flash-lite",
        contents=f"Analyze the following raw server log:\n{raw_log}",
        config=types.GenerateContentConfig(
            system_instruction=SYSTEM_PROMPT,
            temperature=0.0,
            response_mime_type="application/json",
            response_schema=LogAnalysis,
        ),
    )
    # Validate and deserialize JSON string directly into the Pydantic object
    return LogAnalysis.model_validate_json(response.text)

if __name__ == "__main__":
    sample = (
        "2026-10-15 02:11:44 [ALERT] sshd[9012]: Accepted password for root "
        "from 198.51.100.77 port 44122 ssh2 (ErrorCode=401 bypassed via PAM bug)"
    )
    print(parse_server_log(sample).model_dump_json(indent=2))

# --- Automated Unit Test (Run with: pytest test_module2_structured.py) ---
def test_ssh_breach_log_parsing():
    sample_log = (
        "2026-10-15 02:11:44 [ALERT] sshd[9012]: Accepted password for root "
        "from 198.51.100.77 port 44122 ssh2 (ErrorCode=401 bypassed via PAM bug)"
    )
    result = parse_server_log(sample_log)

    assert result.severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]
    assert result.error_code == 401
    assert result.is_compromised is True
    assert len(result.recommended_fix) >= 1
