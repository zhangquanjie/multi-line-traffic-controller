from datetime import datetime
from typing import Literal
from pydantic import BaseModel, Field, field_validator, model_validator
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


class LineIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    firewall_id: int = Field(gt=0)
    interface: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9\-]*(?:\s+)?[0-9/]+(?:\.[0-9]+)?$")
    if_index: int = Field(gt=0)
    quota_gb: float = Field(gt=0)
    billing_day: int = Field(ge=1, le=31)
    enabled: bool = True
    auto_shutdown: bool = True


class AdjustmentIn(BaseModel):
    total_gb: float = Field(ge=0)
    note: str = Field(default="运营商数据校准", max_length=500)


class CycleIn(BaseModel):
    billing_day: int = Field(ge=1, le=31)


class FirewallIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    firewall_host: str
    firewall_port: int = Field(ge=1, le=65535)
    firewall_username: str
    firewall_password: str = ""
    snmp_host: str
    snmp_port: int = Field(ge=1, le=65535)
    snmp_version: Literal["v2c", "v3"] = "v2c"
    snmp_community: str = ""
    snmp_v3_username: str = Field(default="", max_length=128)
    snmp_v3_security_level: Literal["noAuthNoPriv", "authNoPriv", "authPriv"] = "authPriv"
    snmp_v3_auth_protocol: Literal["MD5", "SHA", "SHA224", "SHA256", "SHA384", "SHA512"] = "SHA"
    snmp_v3_auth_password: str = ""
    snmp_v3_priv_protocol: Literal["DES", "AES", "AES192", "AES256"] = "AES"
    snmp_v3_priv_password: str = ""
    snmp_v3_context: str = Field(default="", max_length=128)

    @field_validator("firewall_host", "snmp_host")
    @classmethod
    def strip_host(cls, value: str) -> str:
        return value.strip()

    @model_validator(mode="after")
    def validate_v3_identity(self):
        if self.snmp_version == "v3" and not self.snmp_v3_username.strip():
            raise ValueError("SNMP v3 必须填写用户名")
        return self


class SettingsIn(BaseModel):
    poll_seconds: int = Field(ge=30, le=86400)
    dry_run: bool = True
    timezone: str = Field(default="Asia/Shanghai", max_length=64)

    @field_validator("timezone")
    @classmethod
    def valid_timezone(cls, value: str) -> str:
        try:
            ZoneInfo(value)
        except (ZoneInfoNotFoundError, ValueError):
            raise ValueError("无效时区")
        return value


