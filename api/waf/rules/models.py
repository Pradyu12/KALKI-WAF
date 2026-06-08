from pydantic import BaseModel, Field


class RuleCreate(BaseModel):
    identifier: str = Field(..., description="Unique human-readable identifier")
    pattern: str = Field(..., description="Valid Python regular expression string")
    action: str = Field(..., description="Drop & Blacklist, JS Challenge, or Log Payload Only")
    category: str = "Custom"
    severity: str = "Level 2"
    description: str = ""


class ToggleRuleRequest(BaseModel):
    is_active: bool


class PostureUpdate(BaseModel):
    posture: str


class SandboxTestRequest(BaseModel):
    pattern: str
    payload: str


class IPBlacklistRequest(BaseModel):
    ip_address: str
    reason: str = "Manual block"
    duration_hours: int = 24


class RuleImportItem(BaseModel):
    identifier: str = Field(..., description="Unique human-readable rule name")
    pattern: str = Field(..., description="Valid Python regular expression")
    action: str = Field(
        default="Drop & Blacklist",
        description="Drop & Blacklist | JS Challenge | Log Payload Only | Rate Limit | Block",
    )
    category: str = Field(default="Custom", description="Threat category (SQLi, XSS, CMDi, etc.)")
    severity: str = Field(default="Level 2", description="CRITICAL | Level 1 | Level 2 | Level 3")
    description: str = ""


class SandboxMatchRequest(BaseModel):
    payload: str
    category: str | None = None


class ImportRulesRequest(BaseModel):
    rules: list[RuleImportItem]
    overwrite: bool = False
    source: str = "custom"
