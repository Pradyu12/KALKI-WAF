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
