from dataclasses import dataclass, field
from typing import List

@dataclass
class DomainScore:
    name: str
    score: int
    details: str

@dataclass
class ContainerReport:
    container_name: str
    risk_score: int
    domains: List[DomainScore] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
