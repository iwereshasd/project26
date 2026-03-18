from .models import DomainScore, ContainerReport


class Analyzer:
    DOMAIN_WEIGHTS = {
        "privileges": 0.3,
        "filesystem": 0.25,
        "network": 0.2,
        "kernel_security": 0.15,
        "runtime": 0.1
    }

    def analyze(self, inspect_data) -> ContainerReport:
        name = inspect_data.get('Name', '').strip('/')

        host = inspect_data.get('HostConfig', {})
        config = inspect_data.get('Config', {})
        mounts = inspect_data.get('Mounts', [])

        domains = []

        # -----------------
        # 1. PRIVILEGES
        # -----------------
        score = 0
        details = []

        user = config.get('User') or "root"
        privileged = host.get('Privileged', False)

        if user == "root":
            score += 4
            details.append("container runs as root")

        if privileged:
            score += 6
            details.append("privileged mode enabled")

        caps = host.get('CapAdd') or []
        dangerous_caps = {"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE"}

        bad_caps = [c for c in caps if c in dangerous_caps]
        if bad_caps:
            score += 3
            details.append(f"dangerous capabilities: {bad_caps}")

        domains.append(DomainScore(
            "privileges",
            min(score, 10),
            ", ".join(details) or "no major issues"
        ))

        # -----------------
        # 2. FILESYSTEM
        # -----------------
        score = 0
        details = []

        for m in mounts:
            if m.get('RW'):
                source = m.get('Source', '')
                dest = m.get('Destination', '')

                if dest.startswith(('/proc', '/sys', '/dev')):
                    score += 5
                    details.append(f"critical mount: {dest}")

                elif source.startswith('/'):
                    score += 2
                    details.append(f"writable host mount: {source}")

        if not host.get("ReadonlyRootfs"):
            score += 3
            details.append("root filesystem is writable")

        domains.append(DomainScore(
            "filesystem",
            min(score, 10),
            ", ".join(details) or "no major issues"
        ))

        # -----------------
        # 3. NETWORK
        # -----------------
        score = 0
        details = []

        net_mode = host.get('NetworkMode')

        if net_mode == "host":
            score += 6
            details.append("host network mode")

        ports = config.get("ExposedPorts") or {}
        if len(ports) > 5:
            score += 2
            details.append("many exposed ports")

        domains.append(DomainScore(
            "network",
            min(score, 10),
            ", ".join(details) or "no major issues"
        ))

        # -----------------
        # 4. KERNEL SECURITY
        # -----------------
        score = 0
        details = []

        sec_opts = host.get('SecurityOpt') or []

        if not sec_opts:
            score += 4
            details.append("no security profiles")

        if any("seccomp=unconfined" in s for s in sec_opts):
            score += 5
            details.append("seccomp disabled")

        if any("apparmor=unconfined" in s for s in sec_opts):
            score += 4
            details.append("apparmor disabled")

        domains.append(DomainScore(
            "kernel_security",
            min(score, 10),
            ", ".join(details) or "no major issues"
        ))

        # -----------------
        # 5. RUNTIME
        # -----------------
        score = 0
        details = []

        if not host.get('Memory'):
            score += 4
            details.append("no memory limit")

        if not host.get('PidsLimit'):
            score += 3
            details.append("no PID limit")

        domains.append(DomainScore(
            "runtime",
            min(score, 10),
            ", ".join(details) or "no major issues"
        ))

        # -----------------
        # TOTAL SCORE
        # -----------------
        total_score = sum(
            d.score * self.DOMAIN_WEIGHTS[d.name]
            for d in domains
        )

        total_score = int(total_score * 10)  # нормализация 0–100

        # -----------------
        # RISK LEVEL
        # -----------------
        if total_score < 20:
            level = "LOW"
        elif total_score < 40:
            level = "MEDIUM"
        elif total_score < 70:
            level = "HIGH"
        else:
            level = "CRITICAL"

        # -----------------
        # RECOMMENDATIONS
        # -----------------
        recommendations = []

        if user == "root":
            recommendations.append("Run container as non-root user")

        if privileged:
            recommendations.append("Disable privileged mode")

        if bad_caps:
            recommendations.append("Drop unnecessary Linux capabilities")

        if not host.get("ReadonlyRootfs"):
            recommendations.append("Enable read-only root filesystem")

        if net_mode == "host":
            recommendations.append("Avoid host network mode")

        if not sec_opts:
            recommendations.append("Apply security profiles (seccomp/apparmor)")

        if not host.get('Memory'):
            recommendations.append("Set memory limits")

        if not host.get('PidsLimit'):
            recommendations.append("Set PID limits")

        # удаляем дубликаты
        recommendations = list(set(recommendations))

        return ContainerReport(
            name,
            total_score,
            domains,
            recommendations,
            level
        )