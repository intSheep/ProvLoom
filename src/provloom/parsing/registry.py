from __future__ import annotations

from provloom.domain.raw_models import RawEvent
from provloom.parsing.interfaces import LogParser, ParserRegistry
from provloom.parsing.parsers.app_log import ApplicationLogParser
from provloom.parsing.parsers.asset_parser import AssetManifestParser
from provloom.parsing.parsers.auditbeat import AuditbeatParser
from provloom.parsing.parsers.auth_log import AuthLogParser
from provloom.parsing.parsers.firewall_csv import FirewallParser
from provloom.parsing.parsers.generic import GenericJsonCsvParser
from provloom.parsing.parsers.powershell import PowerShellParser
from provloom.parsing.parsers.sysmon import SysmonParser
from provloom.parsing.parsers.zeek_json import ZeekJsonParser


class DefaultParserRegistry(ParserRegistry):
    def __init__(self) -> None:
        self._parsers: list[LogParser] = []
        self._fallback = GenericJsonCsvParser()

    def register(self, parser: LogParser) -> None:
        self._parsers.append(parser)

    def resolve(self, raw_event: RawEvent) -> LogParser:
        for parser in self._parsers:
            if parser.supports(raw_event):
                return parser
        return self._fallback

    @classmethod
    def with_defaults(cls) -> DefaultParserRegistry:
        reg = cls()
        for p in (
            SysmonParser(),
            PowerShellParser(),
            AuditbeatParser(),
            ZeekJsonParser(),
            FirewallParser(),
            AuthLogParser(),
            ApplicationLogParser(),
            AssetManifestParser(),
        ):
            reg.register(p)
        return reg
