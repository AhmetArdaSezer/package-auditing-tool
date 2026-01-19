
2.4 SBOM Parsing
CycloneDX:
pythonimport json

def parse_cyclonedx_sbom(sbom_path):
    with open(sbom_path) as f:
        sbom = json.load(f)
    
    packages = []
    for component in sbom.get('components', []):
        pkg = {
            'name': component['name'],
            'version': component['version'],
            'type': component.get('type'),
            'purl': component.get('purl'),
            'cpe': component.get('cpe')
        }
        
        # Extract licenses
        if 'licenses' in component:
            pkg['licenses'] = [l.get('license', {}).get('id') for l in component['licenses']]
        
        packages.append(pkg)
    
    return packages
SPDX:
pythondef parse_spdx_sbom(sbom_path):
    with open(sbom_path) as f:
        sbom = json.load(f)
    
    packages = []
    for pkg_info in sbom.get('packages', []):
        purl = None
        cpe = None
        
        # Extract PURL and CPE from externalRefs
        for ref in pkg_info.get('externalRefs', []):
            if ref['referenceCategory'] == 'PACKAGE-MANAGER':
                if ref['referenceType'] == 'purl':
                    purl = ref['referenceLocator']
            elif ref['referenceCategory'] == 'SECURITY':
                if ref['referenceType'] == 'cpe23Type':
                    cpe = ref['referenceLocator']
        
        pkg = {
            'name': pkg_info['name'],
            'version': pkg_info.get('versionInfo', 'unknown'),
            'purl': purl,
            'cpe': cpe,
            'supplier': pkg_info.get('supplier'),
            'license': pkg_info.get('licenseConcluded')
        }
        
        packages.append(pkg)
    
    return packages
2.5 Vulnerability Prioritization
pythondef prioritize_vulnerabilities(vulnerabilities):
    """Score and rank vulnerabilities"""
    
    def calculate_priority_score(vuln):
        score = 0
        
        # CVSS base score (0-100)
        score += vuln.get('cvss_score', 0) * 10
        
        # Exploitability (+30)
        if vuln.get('has_exploit'):
            score += 30
        
        # CISA KEV (+20)
        if vuln.get('in_kev'):
            score += 20
        
        # Public PoC (+10)
        if vuln.get('public_poc'):
            score += 10
        
        # Recency (-age/365 * 5)
        age_days = (time.time() - vuln.get('published', 0)) / 86400
        score -= min(age_days / 365 * 5, 5)
        
        return score
    
    # Add priority scores
    for vuln in vulnerabilities:
        vuln['priority_score'] = calculate_priority_score(vuln)
    
    # Sort by priority
    vulnerabilities.sort(key=lambda v: v['priority_score'], reverse=True)
    
    return vulnerabilities

def check_cisa_kev(cve_id):
    """Check if CVE is in CISA Known Exploited Vulnerabilities"""
    kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    
    try:
        response = requests.get(kev_url, timeout=10)
        kev_data = response.json()
        
        for vuln in kev_data.get('vulnerabilities', []):
            if vuln['cveID'] == cve_id:
                return True, vuln.get('dueDate')
    except Exception as e:
        logging.error(f"KEV check failed: {e}")
    
    return False, None

3. BENZER AÇIK KAYNAK PROJELER
3.1 Vuls (Go)
Repository: github.com/future-architect/vuls
Özellikler:

Agentless scanning (SSH/local)
15+ Linux distro desteği
Offline mode
OVAL/GOST/CPE matching
Web UI (VulsRepo)

Mimari:
config.toml → scan → detect → report
              ↓        ↓         ↓
           SSH/Local  OVAL    JSON/Slack
config.toml örneği:
toml[servers.server1]
host = "192.168.1.10"
port = "22"
user = "vuls-user"
keyPath = "/home/vuls/.ssh/id_rsa"

[cveDict]
type = "sqlite3"
SQLite3Path = "/var/log/vuls/cve.sqlite3"

[ovalDict]
type = "sqlite3"
SQLite3Path = "/var/log/vuls/oval.sqlite3"
Kullanım:
bash# Prepare databases
go-cve-dictionary fetchnvd -years 2020,2021,2022,2023,2024
goval-dictionary fetch-ubuntu 20 22

# Scan
vuls scan
vuls report -format-json -to-localfile
3.2 cve-bin-tool (Python)
Repository: github.com/ossf/cve-bin-tool
Özellikler:

365+ built-in checkers
Binary scanning
SBOM support (SPDX, CycloneDX)
Package list scanning
Multi-source (NVD, OSV, GitLab, RedHat)

Kullanım:
bash# Package list
dpkg -l | cve-bin-tool -

# Binary scan
cve-bin-tool /usr/bin/curl

# SBOM
cve-bin-tool --sbom cyclonedx --sbom-file sbom.json

# Output formats
cve-bin-tool --format csv -o report.csv
Config (~/.config/cve-bin-tool/cve-bin-tool.conf):
ini[cve-bin-tool]
nvd_api_key = your_api_key_here
cache_directory = /var/cache/cve-bin-tool
update_frequency = 1
severity = medium
3.3 Trivy (Go)
Repository: github.com/aquasecurity/trivy
Özellikler:

Container image scanning
Filesystem scanning
Git repository scanning
IaC misconfiguration
Secret detection
License scanning

Kullanım:
bash# Image scan
trivy image alpine:3.15

# Filesystem
trivy fs /path/to/project

# SBOM generation
trivy image --format spdx-json -o sbom.json alpine:3.15

# Filter by severity
trivy image --severity HIGH,CRITICAL nginx
trivy.yaml:
yamlscan:
  security-checks:
    - vuln
    - config
    - secret
  
vulnerability:
  type:
    - os
    - library
  
db:
  repository: ghcr.io/aquasecurity/trivy-db
  
cache:
  dir: /tmp/trivy/cache
3.4 Grype (Go)
Repository: github.com/anchore/grype
Özellikler:

Syft SBOM integration
Container/directory/SBOM scanning
Multi-source vulnerability matching
JSON/table/CycloneDX output

Kullanım:
bash# Quick scan
grype alpine:latest

# SBOM input
syft alpine:latest -o json > sbom.json
grype sbom:./sbom.json

# Filter
grype alpine:latest --only-fixed
.grype.yaml:
yamldb:
  cache-dir: /tmp/grype/db
  update-url: https://toolbox-data.anchore.io/grype/databases/listing.json

match:
  java:
    using-cpes: true
  
search:
  scope: all-layers
3.5 OSV-Scanner (Go)
Repository: github.com/google/osv-scanner
Özellikler:

OSV.dev database
Lockfile scanning (npm, pip, cargo, go.mod)
SBOM input/output
Container scanning
Offline mode

Kullanım:
bash# Lockfile scan
osv-scanner --lockfile=package-lock.json

# Directory scan
osv-scanner /path/to/project

# SBOM
osv-scanner --sbom=sbom.json

# Docker
osv-scanner --docker alpine:latest
3.6 Karşılaştırma Matrisi
ÖzellikVulscve-bin-toolTrivyGrypeOSV-ScannerDilGoPythonGoGoGoAgentless✅❌❌❌❌dpkg/rpm✅✅✅✅❌Container❌❌✅✅✅SBOM In❌✅✅✅✅SBOM Out❌✅✅✅✅Binary Scan❌✅❌❌❌IaC❌❌✅❌❌Offline✅✅✅✅✅Web UI✅❌❌❌❌Hız⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐DB KaynaklarıNVD, OVALNVD, OSV, RHNVD, GitHubNVD, GitHubOSV.dev
Seçim Kriterleri:

Vuls: Enterprise agentless scanning, multi-server management
cve-bin-tool: Binary analysis, SBOM flexibility
Trivy: All-in-one solution (container + IaC + secrets)
Grype: SBOM-first workflow, Syft integration
OSV-Scanner: Developer-focused, lockfile scanning


4. KRİTİK YAPILANDIRMA VE GÜVENLİK
4.1 YAML Konfigürasyon Şeması
yaml# /etc/vuln-scanner/config.yaml

# Metadata
scanner:
  name: "linux-vuln-scanner"
  version: "1.0.0"
  user_agent: "LinuxVulnScanner/1.0"

# Vulnerability sources
sources:
  nvd:
    enabled: true
    api_url: "https://services.nvd.nist.gov/rest/json/cves/2.0"
    api_key: "${NVD_API_KEY}"  # Environment variable
    rate_limit: 5  # requests per 30 seconds (without key)
    timeout: 30
    retry_attempts: 3
    
  osv:
    enabled: true
    api_url: "https://api.osv.dev/v1"
    timeout: 15
    batch_size: 100
    
  debian:
    enabled: true
    tracker_url: "https://security-tracker.debian.org/tracker/data/json"
    cache_ttl: 43200  # 12 hours
    
  redhat:
    enabled: true
    oval_base_url: "https://www.redhat.com/security/data/oval/"
    supported_versions: [7, 8, 9]

# Caching
cache:
  backend: "sqlite"  # sqlite | redis | none
  sqlite:
    path: "/var/cache/vuln-scanner/cache.db"
    max_size_mb: 1024
  redis:
    host: "localhost"
    port: 6379
    db: 0
    password: "${REDIS_PASSWORD}"
  ttl:
    nvd: 86400  # 24 hours
    osv: 21600  # 6 hours
    debian: 43200  # 12 hours
  cleanup_interval: 3600  # 1 hour

# Scanning
scan:
  parallel_workers: 10
  batch_size: 100
  timeout_per_package: 10
  
  # Package filtering
  exclude_patterns:
    - "^linux-image-.*"
    - "^linux-headers-.*"
    - "^linux-modules-.*"
  
  include_dev_packages: false
  
  # Distro detection
  auto_detect_distro: true
  fallback_distro: "debian"

# Reporting
reporting:
  formats:
    - json
    - html
    - csv
    - markdown
  
  output:
    directory: "/var/reports/vuln-scanner"
    filename_template: "scan_{timestamp}_{hostname}.{format}"
    
  severity_threshold: "MEDIUM"  # CRITICAL | HIGH | MEDIUM | LOW | NONE
  
  include_fixed: true
  include_unfixed: true
  
  fields:
    - cve_id
    - package_name
    - installed_version
    - fixed_version
    - cvss_score
    - severity
    - description
    - references
    - published_date

# Logging
logging:
  level: "INFO"  # DEBUG | INFO | WARNING | ERROR | CRITICAL
  format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
  
  handlers:
    file:
      enabled: true
      path: "/var/log/vuln-scanner/scanner.log"
      max_bytes: 10485760  # 10MB
      backup_count: 5
    
    console:
      enabled: true
      colorize: true
    
    syslog:
      enabled: false
      address: "/dev/log"
      facility: "user"

# Security
security:
  verify_ssl: true
  ssl_cert_path: null  # Custom CA bundle
  proxy:
    http: null  # "http://proxy:8080"
    https: null
  
  credentials:
    encryption_key: "${ENCRYPTION_KEY}"
    keyring_backend: "system"  # system | file | none

# Notifications
notifications:
  enabled: false
  
  slack:
    webhook_url: "${SLACK_WEBHOOK}"
    channel: "#security-alerts"
    severity_threshold: "HIGH"
  
  email:
    smtp_server: "smtp.example.com"
    smtp_port: 587
    from_address: "scanner@example.com"
    to_addresses:
      - "security@example.com"
    severity_threshold: "CRITICAL"

# Performance
performance:
  connection_pool_size: 20
  dns_cache_ttl: 300
  http_keep_alive: true
  
  memory:
    max_cache_items: 10000
    gc_threshold: 0.8  # 80% memory usage

# Experimental features
experimental:
  machine_learning_scoring: false
  github_advisories: true
  exploit_prediction: false
4.2 Güvenlik En İyi Uygulamalar
1. Credential Management:
pythonimport os
from cryptography.fernet import Fernet
import keyring

class CredentialManager:
    def __init__(self):
        self.encryption_key = os.getenv('ENCRYPTION_KEY')
        if not self.encryption_key:
            raise ValueError("ENCRYPTION_KEY not set")
        
        self.cipher = Fernet(self.encryption_key.encode())
    
    def get_api_key(self, service='nvd'):
        """Retrieve API key from system keyring"""
        try:
            encrypted_key = keyring.get_password('vuln-scanner', service)
            if encrypted_key:
                return self.cipher.decrypt(encrypted_key.encode()).decode()
        except Exception as e:
            logging.error(f"Failed to retrieve key: {e}")
        
        # Fallback to environment variable
        return os.getenv(f"{service.upper()}_API_KEY")
    
    def store_api_key(self, service, api_key):
        """Store encrypted API key"""
        encrypted = self.cipher.encrypt(api_key.encode())
        keyring.set_password('vuln-scanner', service, encrypted.decode())
2. Input Validation:
pythonimport re

class InputValidator:
    PACKAGE_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9._+-]+$')
    VERSION_PATTERN = re.compile(r'^[0-9a-zA-Z._+-:~]+$')
    
    @staticmethod
    def validate_package_name(name):
        if not InputValidator.PACKAGE_NAME_PATTERN.match(name):
            raise ValueError(f"Invalid package name: {name}")
        
        if len(name) > 255:
            raise ValueError("Package name too long")
        
        return name
    
    @staticmethod
    def validate_version(version):
        if not InputValidator.VERSION_PATTERN.match(version):
            raise ValueError(f"Invalid version: {version}")
        
        # Remove potential injection attempts
        dangerous_chars = [';', '&', '|', '`', '$', '(', ')']
        for char in dangerous_chars:
            if char in version:
                raise ValueError(f"Dangerous character in version: {char}")
        
        return version
    
    @staticmethod
    def sanitize_path(path):
        """Prevent path traversal"""
        import os.path
        
        # Resolve to absolute path
        abs_path = os.path.abspath(path)
        
        # Check if within allowed directory
        allowed_base = os.path.abspath('/var/reports')
        if not abs_path.startswith(allowed_base):
            raise ValueError("Path traversal detected")
        
        return abs_path
3. Subprocess Security:
pythonimport subprocess
import shlex

def run_command_safe(command_args, timeout=60):
    """
    NEVER use shell=True
    Always use list arguments
    """
    
    # Validate command
    if not isinstance(command_args, list):
        raise TypeError("Command must be a list")
    
    # Whitelist allowed commands
    allowed_commands = ['dpkg-query', 'rpm', 'apt-cache']
    if command_args[0] not in allowed_commands:
        raise ValueError(f"Command not allowed: {command_args[0]}")
    
    try:
        result = subprocess.run(
            command_args,
            capture_output=True,
            text=True,
            check=True,
            timeout=timeout,
            shell=False  # CRITICAL: Never True
        )
        return result.stdout
    
    except subprocess.TimeoutExpired:
        raise TimeoutError(f"Command timed out: {command_args}")
    
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Command failed: {e.stderr}")

# Usage
output = run_command_safe(['dpkg-query', '-W', '-f=${binary:Package}\n'])
4. File System Permissions:
bash#!/bin/bash

# Create dedicated user
sudo useradd -r -s /bin/false vuln-scanner

# Directory structure
sudo mkdir -p /etc/vuln-scanner
sudo mkdir -p /var/cache/vuln-scanner
sudo mkdir -p /var/log/vuln-scanner
sudo mkdir -p /var/reports/vuln-scanner

# Set ownership
sudo chown -R vuln-scanner:vuln-scanner /var/cache/vuln-scanner
sudo chown -R vuln-scanner:vuln-scanner /var/log/vuln-scanner
sudo chown -R vuln-scanner:vuln-scanner /var/reports/vuln-scanner
sudo chown root:vuln-scanner /etc/vuln-scanner

# Set permissions
sudo chmod 750 /var/cache/vuln-scanner
sudo chmod 750 /var/log/vuln-scanner
sudo chmod 750 /var/reports/vuln-scanner
sudo chmod 750 /etc/vuln-scanner

# Config file (contains secrets)
sudo chmod 640 /etc/vuln-scanner/config.yaml

# Executable
sudo chmod 755 /usr/local/bin/vuln-scanner
sudo chown root:root /usr/local/bin/vuln-scanner
5. Network Security:
pythonimport requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3

class SecureHTTPClient:
    def __init__(self, verify_ssl=True, proxy=None, timeout=30):
        self.session = requests.Session()
        
        # SSL verification
        self.session.verify = verify_ssl
        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        # Retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "POST"]
        )
        
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=10,
            pool_maxsize=20
        )
        
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
        
        # Proxy
        if proxy:
            self.session.proxies = {
                'http': proxy.get('http'),
                'https': proxy.get('https')
            }
        
        # Timeouts
        self.timeout = timeout
        
        # Headers
        self.session.headers.update({
            'User-Agent': 'LinuxVulnScanner/1.0',
            'Accept': 'application/json'
        })
    
    def get(self, url, params=None):
        """Secure GET request"""
        response = self.session.get(
            url,
            params=params,
            timeout=self.timeout
        )
        response.raise_for_status()
        return response.json()
    
    def post(self, url, json=None):
        """Secure POST request"""
        response = self.session.post(
            url,
            json=json,
            timeout=self.timeout
        )
        response.raise_for_status()
        return response.json()
6. Race Condition Protection:
pythonimport fcntl
import contextlib

@contextlib.contextmanager
def file_lock(file_path, mode='r'):
    """Context manager for file locking"""
    with open(file_path, mode) as f:
        try:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            yield f
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)

# Usage
with file_lock('/var/cache/vuln-scanner/cache.db', 'r+') as f:
    data = f.read()
    # Process data
    f.seek(0)
    f.write(updated_data)
    f.truncate()
7. Privilege Separation:
pythonimport os
import pwd
import grp

def drop_privileges(user='vuln-scanner', group='vuln-scanner'):
    """Drop root privileges after initialization"""
    
    if os.getuid() != 0:
        # Already non-root
        return
    
    try:
        # Get user/group info
        pwnam = pwd.getpwnam(user)
        grnam = grp.getgrnam(group)
        
        # Remove supplementary groups
        os.setgroups([])
        
        # Set GID and UID
        os.setgid(grnam.gr_gid)
        os.setuid(pwnam.pw_uid)
        
        # Verify
        assert os.getuid() == pwnam.pw_uid
        assert os.getgid() == grnam.gr_gid
        
        logging.info(f"Dropped privileges to {user}:{group}")
    
    except Exception as e:
        logging.error(f"Failed to drop privileges: {e}")
        raise

# Main application
if __name__ == '__main__':
    # Initialize (may need root for certain operations)
    init_application()
    
    # Drop privileges before processing user input
    drop_privileges()
    
    # Run scanner
    run_scanner()
4.3 Performance Tuning
Optimal Configuration (1000 packages):
yaml# Tuned for 1000 package scan
scan:
  parallel_workers: 16  # 2x CPU cores
  batch_size: 100  # API batch requests
  timeout_per_package: 10

cache:
  backend: "sqlite"
  ttl:
    nvd: 86400  # 24h (NVD updates daily)
    osv: 21600  # 6h (OSV updates frequently)

performance:
  connection_pool_size: 20
  http_keep_alive: true
  dns_cache_ttl: 300

sources:
  nvd:
    rate_limit: 50  # With API key
  osv:
    batch_size: 100
Memory Profiling:
pythonimport tracemalloc
import psutil
import os

def monitor_memory(func):
    def wrapper(*args, **kwargs):
        tracemalloc.start()
        process = psutil.Process(os.getpid())
        
        # Before
        mem_before = process.memory_info().rss / 1024 / 1024
        
        # Execute
        result = func(*args, **kwargs)
        
        # After
        mem_after = process.memory_info().rss / 1024 / 1024
        current, peak = tracemalloc.get_traced_memory()
        
        print(f"Memory usage: {mem_before:.2f}MB → {mem_after:.2f}MB")
        print(f"Peak allocated: {peak / 1024 / 1024:.2f}MB")
        
        tracemalloc.stop()
        return result
    
    return wrapper

@monitor_memory
def scan_all_packages():
    # Scan implementation
    pass
4.4 Monitoring & Alerting
Prometheus Metrics:
pythonfrom prometheus_client import Counter, Histogram, Gauge, start_http_server

# Define metrics
scan_requests = Counter('scan_requests_total', 'Total scan requests')
scan_duration = Histogram('scan_duration_seconds', 'Scan duration')
packages_scanned = Counter('packages_scanned_total', 'Packages scanned')
vulnerabilities_found = Gauge(
    'vulnerabilities_found',
    'Current vulnerabilities by severity',
    ['severity']
)
api_errors = Counter('api_errors_total', 'API errors', ['source'])

# Instrumentation
@scan_duration.time()
def scan_system():
    scan_requests.inc()
    
    packages = get_packages()
    packages_scanned.inc(len(packages))
    
    for pkg in packages:
        try:
            vulns = scan_package(pkg)
            for v in vulns:
                vulnerabilities_found.labels(
                    severity=v['severity']
                ).inc()
        except APIError as e:
            api_errors.labels(source=e.source).inc()

# Start metrics server
start_http_server(8000)
Health Check:
pythonfrom flask import Flask, jsonify

app = Flask(__name__)

@app.route('/health')
def health_check():
    checks = {
        'cache': check_cache(),
        'nvd_api': check_nvd(),
        'osv_api': check_osv(),
        'disk_space': check_disk_space()
    }
    
    status = 'healthy' if all(checks.values()) else 'unhealthy'
    code = 200 if status == 'healthy' else 503
    
    return jsonify({
        'status': status,
        'timestamp': int(time.time()),
        'checks': checks
    }), code

def check_disk_space():
    """Check if enough disk space available"""
    import shutil
    stat = shutil.disk_usage('/var/cache/vuln-scanner')
    free_gb = stat.free / (1024**3)
    return free_gb > 1.0  # At least 1GB free

REFERANSLAR

NVD API Documentation: https://nvd.nist.gov/developers
OSV.dev: https://osv.dev/
CycloneDX: https://cyclonedx.org/
SPDX: https://spdx.dev/
CVSS Calculator: https://www.first.org/cvss/calculator/3.1
CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
