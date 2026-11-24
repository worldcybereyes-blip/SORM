"""
telecom_generator.py

Generates fully synthetic telecom traffic for the SORM educational simulation.
Phone numbers use the fictional prefix +00555. IP addresses come from the
reserved documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
and private space (10.64.0.0/16). Domains end in example.com / .org / .net.
Nothing here corresponds to a real person, subscriber or network.
"""

import random
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone

DEFAULT_START_TIME = 1767225600.0


@dataclass
class Packet:
    packet_id: str
    timestamp: float
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    size: int
    cell_tower_id: str
    caller_id: str
    callee_id: str
    payload: str

    def to_dict(self):
        return asdict(self)


def iso_time(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class TelecomTrafficGenerator:
    """Produces SIP signaling, SMS logs, HTTP and HTTPS metadata, and IPDR records."""

    PROTOCOLS = ["SIP", "SMS", "HTTP", "HTTPS", "IPDR"]
    WEIGHTS = [25, 20, 20, 25, 10]

    BENIGN_SMS = [
        "Your parcel will arrive today",
        "Meeting moved to 4 PM",
        "Happy birthday! See you tonight",
        "Your OTP is 482913. Do not share it",
        "Recharge successful. Balance updated",
        "Lunch tomorrow?",
        "Your monthly bill has been generated",
    ]
    SENSITIVE_SMS = [
        "Please send the confidential file before noon",
        "Wire-transfer approved, use the new account",
        "Project-falcon status is urgent, call me",
        "Share your credentials for the portal",
    ]
    BENIGN_HOSTS = [
        "news.example.com", "shop.example.org", "video.example.net",
        "mail.example.com", "wiki.example.org", "maps.example.net",
    ]
    SENSITIVE_HOSTS = ["darkmarket-sim.example.net", "leaks-sim.example.org"]
    BENIGN_PATHS = [
        "/", "/index.html", "/search?q=weather", "/api/v1/items?page=2",
        "/login", "/search?q=train+timetable",
    ]
    SENSITIVE_PATHS = ["/search?q=confidential+documents", "/files/project-falcon.zip"]
    USER_AGENTS = ["SimBrowser/5.0", "SimMobile/12.1", "SimApp/3.4"]
    SIP_AGENTS = ["SimPhone/1.0", "SimSoft/2.3", "SimDeskPhone/0.9"]

    def __init__(self, seed=None, subscriber_count=25, tower_count=8,
                 sensitive_ratio=0.12, burst_probability=0.01, start_time=None):
        self.rng = random.Random(seed)
        self.sensitive_ratio = sensitive_ratio
        self.burst_probability = burst_probability
        self.clock = float(start_time if start_time is not None else time.time())
        self.towers = ["TWR-%03d" % (100 + i) for i in range(tower_count)]
        self.subscribers = []
        self.sub_ip = {}
        self.sub_tower = {}
        for i in range(subscriber_count):
            number = "+00555%07d" % (1000 + i)
            self.subscribers.append(number)
            self.sub_ip[number] = "10.64.%d.%d" % (i // 200, 10 + i % 200)
            self.sub_tower[number] = self.towers[i % tower_count]
        self.sequence = 0
        self._fast = False

    # ----- helpers --------------------------------------------------------
    def _tick(self):
        self.clock += 0.05 if self._fast else self.rng.uniform(0.02, 1.5)
        return self.clock

    def _next_id(self):
        self.sequence += 1
        return "PKT-%06d" % self.sequence

    def _hex(self, digits):
        return format(self.rng.getrandbits(4 * digits), "0%dx" % digits)

    def _tower_for(self, number):
        if self.rng.random() < 0.15:
            return self.rng.choice(self.towers)
        return self.sub_tower[number]

    def _public_ip(self):
        if self.rng.random() < 0.03:
            return "203.0.113.66"
        net = self.rng.choice(["192.0.2", "198.51.100", "203.0.113"])
        return "%s.%d" % (net, self.rng.randint(1, 254))

    def _sensitive(self):
        return self.rng.random() < self.sensitive_ratio

    def _packet(self, protocol, src_ip, dst_ip, src_port, dst_port, payload,
                caller, callee, tower, extra=0, overhead=48):
        return Packet(
            packet_id=self._next_id(),
            timestamp=round(self._tick(), 3),
            protocol=protocol,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            size=len(payload) + overhead + extra,
            cell_tower_id=tower,
            caller_id=caller,
            callee_id=callee,
            payload=payload,
        )

    # ----- protocol generators -------------------------------------------
    def generate_sip(self, caller=None, method=None):
        caller = caller or self.rng.choice(self.subscribers)
        if method is None:
            method = self.rng.choices(
                ["INVITE", "BYE", "REGISTER", "OPTIONS", "CANCEL"],
                weights=[45, 25, 15, 10, 5])[0]
        if method in ("REGISTER", "OPTIONS"):
            callee = caller
        else:
            callee = self.rng.choice([s for s in self.subscribers if s != caller])
        src_ip = self.sub_ip[caller]
        lines = [
            "%s sip:%s@ims.example.net SIP/2.0" % (method, callee),
            "Via: SIP/2.0/UDP %s:5060;branch=z9hG4bK%s" % (src_ip, self._hex(10)),
            "Max-Forwards: 70",
            "From: <sip:%s@ims.example.net>;tag=%s" % (caller, self._hex(8)),
            "To: <sip:%s@ims.example.net>" % callee,
            "Call-ID: %s@%s" % (self._hex(16), src_ip),
            "CSeq: %d %s" % (self.rng.randint(1, 200), method),
            "User-Agent: %s" % self.rng.choice(self.SIP_AGENTS),
            "Content-Length: 0",
        ]
        payload = "\r\n".join(lines) + "\r\n\r\n"
        return self._packet("SIP", src_ip, "203.0.113.10", 5060, 5060, payload,
                            caller, callee, self._tower_for(caller))

    def generate_sms(self):
        sender, receiver = self.rng.sample(self.subscribers, 2)
        if self._sensitive():
            text = self.rng.choice(self.SENSITIVE_SMS)
        else:
            text = self.rng.choice(self.BENIGN_SMS)
        status = self.rng.choice(["DELIVERED", "DELIVERED", "DELIVERED", "PENDING", "FAILED"])
        payload = "SMS-LOG|FROM=%s|TO=%s|SMSC=SMSC-01|STATUS=%s|LEN=%d|TEXT=%s" % (
            sender, receiver, status, len(text), text)
        return self._packet("SMS", self.sub_ip[sender], "203.0.113.25",
                            self.rng.randint(40000, 60000), 2775, payload,
                            sender, receiver, self._tower_for(sender))

    def generate_http(self):
        user = self.rng.choice(self.subscribers)
        if self._sensitive():
            host = self.rng.choice(self.SENSITIVE_HOSTS)
            path = self.rng.choice(self.SENSITIVE_PATHS)
        else:
            host = self.rng.choice(self.BENIGN_HOSTS)
            path = self.rng.choice(self.BENIGN_PATHS)
        payload = ("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n"
                   "Accept: */*\r\nConnection: keep-alive\r\n\r\n") % (
            path, host, self.rng.choice(self.USER_AGENTS))
        return self._packet("HTTP", self.sub_ip[user], self._public_ip(),
                            self.rng.randint(40000, 60000), 80, payload,
                            user, "-", self._tower_for(user),
                            extra=self.rng.randint(200, 6000))

    def generate_https(self):
        user = self.rng.choice(self.subscribers)
        if self._sensitive():
            host = self.rng.choice(self.SENSITIVE_HOSTS)
        else:
            host = self.rng.choice(self.BENIGN_HOSTS)
        if self.rng.random() < 0.02:
            enc = self.rng.randint(120000, 600000)
        else:
            enc = self.rng.randint(500, 48000)
        payload = "TLS-META|VERSION=%s|SNI=%s|CIPHER=%s|ENCRYPTED_BYTES=%d" % (
            self.rng.choice(["TLS1.2", "TLS1.3"]), host,
            self.rng.choice(["AES128-GCM", "AES256-GCM", "CHACHA20"]), enc)
        return self._packet("HTTPS", self.sub_ip[user], self._public_ip(),
                            self.rng.randint(40000, 60000), 443, payload,
                            user, "-", self._tower_for(user), extra=enc)

    def generate_ipdr(self):
        user = self.rng.choice(self.subscribers)
        end = self.clock
        start = end - self.rng.uniform(5, 300)
        payload = ("IPDR|SUBSCRIBER=%s|IMSI=00155%010d|PRIVATE_IP=%s|PUBLIC_IP=198.51.100.200|"
                   "NAT_PORTS=%d-%d|DEST_IP=%s|DEST_PORT=%d|PROTO=TCP|START=%s|END=%s|"
                   "BYTES_UP=%d|BYTES_DOWN=%d|APN=internet") % (
            user, self.rng.randint(0, 9999999999), self.sub_ip[user],
            1024, 2047, self._public_ip(), self.rng.choice([80, 443, 8080]),
            iso_time(start), iso_time(end),
            self.rng.randint(1000, 900000), self.rng.randint(5000, 5000000))
        return self._packet("IPDR", "198.51.100.200", "203.0.113.250", 4739, 4739,
                            payload, user, "-", self._tower_for(user))

    # ----- batch interface ------------------------------------------------
    def generate_packet(self, protocol=None):
        if protocol is None:
            protocol = self.rng.choices(self.PROTOCOLS, weights=self.WEIGHTS)[0]
        return {
            "SIP": self.generate_sip,
            "SMS": self.generate_sms,
            "HTTP": self.generate_http,
            "HTTPS": self.generate_https,
            "IPDR": self.generate_ipdr,
        }[protocol]()

    def stream(self, count):
        produced = 0
        while produced < count:
            if self.rng.random() < self.burst_probability:
                caller = self.rng.choice(self.subscribers)
                burst = min(10, count - produced)
                self._fast = True
                for _ in range(burst):
                    yield self.generate_sip(caller=caller, method="INVITE")
                    produced += 1
                self._fast = False
            else:
                yield self.generate_packet()
                produced += 1

    def generate_batch(self, count):
        return list(self.stream(count))
