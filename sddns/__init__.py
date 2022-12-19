import os
import sys
import yaml
import os.path as path
from enum import Enum
from typing import Any, List, Dict, Optional


class RecordType(Enum):
    A = 1
    AAAA = 28
    CNAME = 5
    MX = 15
    TXT = 16
    SRV = 33
    CAA = 257
    SSHFP = 44


class CAAFlag(Enum):
    Issue = "issue"
    Iodef = "iodef"
    IssueWildcard = "issuewild"


class Record:
    def __init__(self, name, record_type: RecordType, data: Any, ttl: Optional[int] = None):
        if name == '@':
            name = ''
        self.name = name
        self.type = record_type
        self.data = data
        self.ttl = ttl


class ARecord(Record):
    def __init__(self, name, ipv4: str, ttl: Optional[int] = None):
        super().__init__(name, RecordType.A, ipv4, ttl)


class AAAARecord(Record):
    def __init__(self, name, ipv6: str, ttl: Optional[int] = None):
        super().__init__(name, RecordType.AAAA, ipv6, ttl)


class CNAMERecord(Record):
    def __init__(self, name, alias: str, ttl: Optional[int] = None):
        if alias[-1] != ".":
            alias += "."
        super().__init__(name, RecordType.CNAME, alias, ttl)


class MXRecord(Record):
    def __init__(self, name, exchange: str, preference: int, ttl: Optional[int] = None):
        if exchange[-1] != ".":
            exchange += "."
        data = {"exchange": exchange, "preference": preference}
        super().__init__(name, RecordType.MX, data, ttl)


class TXTRecord(Record):
    def __init__(self, name, text: str, ttl: Optional[int] = None):
        # fix: semicolon not allowed in dns
        new_text = text.replace(";", "\\;")
        super().__init__(name, RecordType.TXT, new_text, ttl)


class SRVRecord(Record):
    def __init__(self, name, target: str, port: int, priority: int, weight: int, ttl: Optional[int] = None):
        if target[-1] != ".":
            target += "."
        data = {"target": target, "port": port, "priority": priority, "weight": weight}
        super().__init__(name, RecordType.SRV, data, ttl)


class CAARecord(Record):
    def __init__(self, name, flag: int, tag: CAAFlag, value: str, ttl: Optional[int] = None):
        if not (0 <= flag <= 255):
            raise ValueError("CAA Tag must be between 0 and 255")
        data = {"tag": tag.value, "value": value, "flag": flag}
        super().__init__(name, RecordType.CAA, data, ttl)


class SSHFPRecord(Record):
    def __init__(self, name, algo: int, key_type: int, fp: str, ttl: Optional[int] = None):
        data = {"algorithm": algo, "fingerprint_type": key_type, "fingerprint": fp}
        super().__init__(name, RecordType.SSHFP, data, ttl)


class Zone:
    def __init__(self, name: str, default_ttl: int = 60) -> None:
        if name[-1] != ".":
            name += "."
        self.name = name
        self.records = []
        self.default_ttl = default_ttl

    def add_record(self, record: Record) -> 'Zone':
        if record.ttl is None:
            record.ttl = self.default_ttl
        self.records.append(record)
        return self

    def add_records(self, records: List[Record]) -> 'Zone':
        for r in records:
            self.add_record(r)
        return self

    @staticmethod
    def filter_record(records: List[Record], record_type: RecordType) -> List[Record]:
        return list(filter(lambda r: r.type == record_type, records))

    @staticmethod
    def min_ttl(records: List[Record], record_type: RecordType) -> int:
        filtered_records = [r.ttl for r in Zone.filter_record(records, record_type)]
        return min(filtered_records) if len(filtered_records) > 0 else 30

    def zone_rrest(self) -> Dict:
        rrest = {}
        hostnames = set([r.name for r in self.records])
        for hostname in hostnames:
            rrest[hostname] = self.host_rrset(hostname)
        return rrest

    def host_rrset(self, host: str) -> List:
        rrset = []
        host_records = list(filter(lambda r: r.name == host, self.records))
        self.append_rrset_multivalue(rrset, host_records, RecordType.A)
        self.append_rrset_multivalue(rrset, host_records, RecordType.AAAA)
        self.append_rrset_multivalue(rrset, host_records, RecordType.MX)
        self.append_rrset_multivalue(rrset, host_records, RecordType.TXT)
        self.append_rrset_multivalue(rrset, host_records, RecordType.SRV)
        self.append_rrset_multivalue(rrset, host_records, RecordType.CAA)
        self.append_rrset_multivalue(rrset, host_records, RecordType.SSHFP)
        self.append_rrset_lastvalue(rrset, host_records, RecordType.CNAME)
        return rrset

    @staticmethod
    def append_rrset_multivalue(rrset: List, host_records: List[Record], record_type: RecordType) -> None:
        type_records = Zone.filter_record(host_records, record_type)
        if len(type_records) <= 0:
            return
        rrset.append({
            "type": record_type.name,
            "ttl": Zone.min_ttl(type_records, record_type),
            "values": [r.data for r in type_records]
        })

    @staticmethod
    def append_rrset_lastvalue(rrset: List, host_records: List[Record], record_type: RecordType) -> None:
        type_records = Zone.filter_record(host_records, record_type)
        if len(type_records) <= 0:
            return
        rrset.append({
            "type": record_type.name,
            "ttl": Zone.min_ttl(type_records, record_type),
            "value": type_records[-1].data
        })


class Config:
    def __init__(self) -> None:
        self.zones = []

    def add_zone(self, zone: Zone) -> 'Config':
        if zone.name in [z.name for z in self.zones]:
            raise ValueError("Zone already exists")
        self.zones.append(zone)
        return self

    def write_yaml(self, folder: str) -> 'Config':
        os.makedirs(folder, exist_ok=True)
        for zone in self.zones:
            with open(path.abspath(path.join(folder, f"{zone.name}yaml")), "w+", encoding="utf-8") as f:
                f.write(yaml.dump(zone.zone_rrest(), explicit_start=False))
        return self

    def octodns(self, config: str, args: List[str]) -> 'Config':
        octodns_args = args[1:]
        os.system(f"octodns-sync --config-file \"{config}\" " + " ".join(octodns_args))
        return self
