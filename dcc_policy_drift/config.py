from pydantic_settings import BaseSettings
from pydantic import Field, AnyUrl
from pathlib import Path

class Settings(BaseSettings):
    okta_token: str | None = Field(None, env="OKTA_TOKEN")
    okta_org_url: str | None = Field(None, env="OKTA_ORG_URL")

    snapshot_dir: Path = Field(Path("snapshots"), env="SNAPSHOT_DIR")
    tenants_file: Path = Field(Path("tenants.yaml"), env="TENANTS_FILE")

    # Email settings
    smtp_host: str | None = Field(None, env="SMTP_HOST")
    smtp_port: int = Field(587, env="SMTP_PORT")
    smtp_username: str | None = Field(None, env="SMTP_USERNAME")
    smtp_password: str | None = Field(None, env="SMTP_PASSWORD")
    smtp_from: str | None = Field(None, env="SMTP_FROM")
    smtp_to: str | None = Field(None, env="SMTP_TO")

    # Slack & Teams
    slack_webhook_url: str | None = Field(None, env="SLACK_WEBHOOK_URL")
    teams_webhook_url: str | None = Field(None, env="TEAMS_WEBHOOK_URL")
    slack_high_severity_only: bool = Field(True, env="SLACK_HIGH_SEVERITY_ONLY")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings() 