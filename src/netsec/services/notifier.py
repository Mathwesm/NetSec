"""Send bounded automation-failure alerts without including operational payloads."""

import httpx
from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_random_exponential

from netsec.runtime import RuntimeFailureError


class NotificationSettings(BaseSettings):
    """Load Telegram credentials only from the process environment."""

    model_config = SettingsConfigDict(env_prefix="TELEGRAM_", extra="forbid")
    bot_token: SecretStr
    chat_id: SecretStr


@retry(
    stop=stop_after_attempt(3),
    wait=wait_random_exponential(multiplier=1, max=8),
    retry=retry_if_exception_type(RuntimeFailureError),
    reraise=True,
)
def notify_failure(job_name: str, run_id: str) -> None:
    """Alert with a correlation ID, redacting transport exceptions containing credentials."""
    settings = NotificationSettings()
    url = "https://api.telegram.org/bot" + settings.bot_token.get_secret_value() + "/sendMessage"
    try:
        with httpx.Client(timeout=10, follow_redirects=False, trust_env=False) as client:
            response = client.post(
                url,
                json={
                    "chat_id": settings.chat_id.get_secret_value(),
                    "text": f"NetSec job {job_name} failed. Run: {run_id}",
                },
            )
            response.raise_for_status()
            body: object = response.json()
            if not isinstance(body, dict) or body.get("ok") is not True:
                raise RuntimeFailureError("Telegram rejected the failure notification")
    except (httpx.HTTPError, ValueError):
        raise RuntimeFailureError("Failure notification could not be delivered") from None
