import random
import datetime

class SyntheticLogGenerator:
    def __init__(self):
        self.users = [f"usr_eng_{i:03d}" for i in range(1, 40)] + [f"usr_exec_{i:03d}" for i in range(1, 10)]
        self.devices = [f"dev_mac_{i:03d}" for i in range(1, 50)]
        self.ip_pool_us = ["192.168.1." + str(i) for i in range(10, 100)] + ["10.0.4." + str(i) for i in range(10, 50)]
        self.resources = ["/api/v1/auth", "/dashboard/metrics", "/source/repo/core", "/finance/payroll", "/admin/db/export"]

    def generate_batch(self, count=500):
        logs = []
        base_time = datetime.datetime.now() - datetime.timedelta(hours=12)

        for i in range(count):
            user = random.choice(self.users)
            device = random.choice(self.devices)
            ip = random.choice(self.ip_pool_us)
            resource = random.choice(self.resources[:3])
            timestamp = base_time + datetime.timedelta(seconds=random.randint(0, 43200))
            
            hour = timestamp.hour
            is_after_hours = 1 if (hour < 7 or hour > 19) else 0

            logs.append({
                "event_id": f"evt_{i:06d}",
                "timestamp": timestamp.isoformat(),
                "user_id": user,
                "device_id": device,
                "source_ip": ip,
                "geo_location": "US-East",
                "resource_path": resource,
                "login_status": "SUCCESS",
                "failed_attempts_5m": random.choice([0, 0, 0, 1]),
                "session_duration_s": random.randint(300, 7200),
                "bytes_transferred": random.randint(1024, 524288),
                "is_after_hours": is_after_hours,
                "attack_type": "BENIGN"
            })

        now = datetime.datetime.now()
        logs.append({
            "event_id": "evt_threat_01_a",
            "timestamp": now.isoformat(),
            "user_id": "usr_exec_001",
            "device_id": "dev_mac_001",
            "source_ip": "192.168.1.15",
            "geo_location": "US-East",
            "resource_path": "/dashboard/metrics",
            "login_status": "SUCCESS",
            "failed_attempts_5m": 0,
            "session_duration_s": 120,
            "bytes_transferred": 2048,
            "is_after_hours": 0,
            "attack_type": "IMPOSSIBLE_TRAVEL"
        })
        logs.append({
            "event_id": "evt_threat_01_b",
            "timestamp": (now + datetime.timedelta(minutes=4)).isoformat(),
            "user_id": "usr_exec_001",
            "device_id": "dev_mac_999",
            "source_ip": "185.220.101.4",
            "geo_location": "RU-Moscow",
            "resource_path": "/admin/db/export",
            "login_status": "SUCCESS",
            "failed_attempts_5m": 0,
            "session_duration_s": 60,
            "bytes_transferred": 52428800,
            "is_after_hours": 1,
            "attack_type": "IMPOSSIBLE_TRAVEL"
        })

        for i in range(12):
            logs.append({
                "event_id": f"evt_threat_02_{i}",
                "timestamp": (now + datetime.timedelta(seconds=i*2)).isoformat(),
                "user_id": "usr_eng_005",
                "device_id": "dev_mac_005",
                "source_ip": "45.154.255.87",
                "geo_location": "DE-Frankfurt",
                "resource_path": "/api/v1/auth",
                "login_status": "FAILED",
                "failed_attempts_5m": i + 1,
                "session_duration_s": 0,
                "bytes_transferred": 128,
                "is_after_hours": 1,
                "attack_type": "BRUTE_FORCE"
            })

        logs.append({
            "event_id": "evt_threat_03",
            "timestamp": (now + datetime.timedelta(hours=-2)).isoformat(),
            "user_id": "usr_eng_012",
            "device_id": "dev_mac_012",
            "source_ip": "10.0.4.15",
            "geo_location": "US-East",
            "resource_path": "/finance/payroll",
            "login_status": "SUCCESS",
            "failed_attempts_5m": 0,
            "session_duration_s": 3600,
            "bytes_transferred": 104857600,
            "is_after_hours": 1,
            "attack_type": "CREDENTIAL_MISUSE"
        })

        return logs
