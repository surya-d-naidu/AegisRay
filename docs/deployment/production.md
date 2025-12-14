# Production Deployment Guide

Comprehensive guide for deploying AegisRay P2P mesh VPN in production environments, covering infrastructure planning, security hardening, monitoring, and maintenance.

## 📋 Table of Contents

- [Infrastructure Planning](#infrastructure-planning)
- [Production Architecture](#production-architecture)
- [Security Hardening](#security-hardening)
- [High Availability Setup](#high-availability-setup)
- [Monitoring & Alerting](#monitoring--alerting)
- [Backup & Recovery](#backup--recovery)
- [Performance Optimization](#performance-optimization)
- [Maintenance & Updates](#maintenance--updates)

## 🏗️ Infrastructure Planning

### Sizing Guidelines

**Small Deployment (< 50 nodes)**
```yaml
exit_nodes: 2              # Primary + backup
relay_nodes: 1             # Optional relay
coordinator_nodes: 1       # Bootstrap helper

hardware_requirements:
  cpu: "2 cores"
  memory: "4GB RAM"
  storage: "50GB SSD"
  bandwidth: "100 Mbps"
```

**Medium Deployment (50-500 nodes)**  
```yaml
exit_nodes: 3              # Multi-region exits
relay_nodes: 2             # Regional relays
coordinator_nodes: 2       # Redundant coordinators

hardware_requirements:
  cpu: "4-8 cores"
  memory: "8-16GB RAM" 
  storage: "100GB SSD"
  bandwidth: "1 Gbps"
```

**Large Deployment (500+ nodes)**
```yaml
exit_nodes: 6              # Global distribution
relay_nodes: 4             # Per-region relays  
coordinator_nodes: 3       # High availability
load_balancers: 2          # Traffic distribution

hardware_requirements:
  cpu: "8+ cores"
  memory: "32+ GB RAM"
  storage: "500GB SSD"
  bandwidth: "10+ Gbps"
```

### Network Architecture

**Geographic Distribution Strategy:**
```
┌─── Region: US-East ────┐  ┌─── Region: US-West ────┐  ┌─── Region: EU-Central ──┐
│                        │  │                        │  │                         │
│  Exit Node (Primary)   │  │  Exit Node (Secondary) │  │  Exit Node (Tertiary)   │
│  Relay Node           │  │  Relay Node           │  │  Relay Node            │
│  Coordinator          │  │                        │  │  Coordinator           │
│                        │  │                        │  │                         │
└────────────────────────┘  └────────────────────────┘  └─────────────────────────┘
           │                           │                           │
           └─────────────── Mesh Network ───────────────────────┘
```

**IP Address Planning:**
```yaml
# Production IP allocation
mesh_networks:
  production: "100.64.0.0/16"    # Main production mesh
  staging: "100.65.0.0/16"       # Staging environment
  development: "100.66.0.0/16"   # Development testing

# Regional subnets
regional_allocation:
  us_east: "100.64.0.0/18"       # 100.64.0.1 - 100.64.63.254
  us_west: "100.64.64.0/18"      # 100.64.64.1 - 100.64.127.254  
  eu_central: "100.64.128.0/18"  # 100.64.128.1 - 100.64.191.254
  asia_pacific: "100.64.192.0/18" # 100.64.192.1 - 100.64.255.254
```

---

## 🏛️ Production Architecture  

### Multi-Tier Architecture

**Tier 1: Edge/Exit Nodes**
- Internet gateways with public IPs
- High-bandwidth connections
- Geographic distribution
- DDoS protection

**Tier 2: Core Relay Nodes**  
- Internal mesh routing
- Inter-region connectivity
- Load balancing
- Redundant paths

**Tier 3: Access Nodes**
- Client connectivity
- Authentication
- Policy enforcement
- Local caching

### Infrastructure as Code

**Terraform Configuration:**
```hcl
# terraform/main.tf
variable "regions" {
  default = ["us-east-1", "us-west-2", "eu-central-1"]
}

resource "aws_instance" "aegisray_exit" {
  count         = length(var.regions)
  ami           = var.aegisray_ami
  instance_type = "c5.2xlarge"
  
  availability_zone = data.aws_availability_zones.available.names[count.index]
  
  vpc_security_group_ids = [aws_security_group.aegisray.id]
  key_name              = aws_key_pair.aegisray.key_name
  
  user_data = templatefile("scripts/install-aegisray.sh", {
    node_type    = "exit"
    region       = var.regions[count.index]
    mesh_network = "production"
  })
  
  tags = {
    Name = "aegisray-exit-${var.regions[count.index]}"
    Type = "exit-node"
    Environment = "production"
  }
}

resource "aws_security_group" "aegisray" {
  name = "aegisray-production"
  
  # AegisRay mesh traffic
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  # Management API (restricted)
  ingress {
    from_port   = 8080
    to_port     = 8080  
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]  # Internal only
  }
  
  # SSH access (bastion only)
  ingress {
    from_port       = 22
    to_port         = 22
    protocol        = "tcp" 
    security_groups = [aws_security_group.bastion.id]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
```

**Docker Compose for Production:**
```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  aegisray-exit:
    image: aegisray/mesh:1.0.0
    container_name: aegisray-exit-prod
    restart: always
    
    # Production configuration
    environment:
      - AEGISRAY_NODE_TYPE=exit
      - AEGISRAY_ENVIRONMENT=production
      - AEGISRAY_LOG_LEVEL=info
      - AEGISRAY_MESH_NETWORK=production
    
    # Security context
    cap_add:
      - NET_ADMIN      # Required for TUN interface
    cap_drop:
      - ALL
    
    # Resource limits  
    deploy:
      resources:
        limits:
          cpus: '4.0'
          memory: 8G
        reservations:
          cpus: '2.0'
          memory: 4G
    
    # Health checks
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 60s
    
    # Network configuration
    networks:
      - aegis-prod
    ports:
      - "443:443"      # Mesh traffic
      - "127.0.0.1:8080:8080"  # Management API (localhost only)
    
    # Persistent data
    volumes:
      - aegis-certs:/etc/aegisray/certs:ro
      - aegis-config:/etc/aegisray/config:ro
      - aegis-logs:/var/log/aegisray
      
    # Configuration files
    configs:
      - source: aegis-prod-config
        target: /etc/aegisray/node.yaml
        mode: 0644

  # Monitoring sidecar
  prometheus-node-exporter:
    image: prom/node-exporter:latest
    container_name: node-exporter
    restart: always
    ports:
      - "127.0.0.1:9100:9100"
    command:
      - '--path.procfs=/host/proc'
      - '--path.rootfs=/rootfs'
      - '--path.sysfs=/host/sys'
      - '--collector.filesystem.ignored-mount-points'
      - '^/(sys|proc|dev|host|etc|rootfs/var/lib/docker/containers|rootfs/var/lib/docker/overlay2|rootfs/run/docker/netns|rootfs/var/lib/docker/aufs)($$|/)'
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro  
      - /:/rootfs:ro

networks:
  aegis-prod:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16

volumes:
  aegis-certs:
    driver: local
  aegis-config:
    driver: local  
  aegis-logs:
    driver: local

configs:
  aegis-prod-config:
    file: ./configs/production.yaml
```

### Kubernetes Deployment

**Production Kubernetes Manifests:**
```yaml
# k8s/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: aegisray-prod
  labels:
    name: aegisray-prod
    environment: production

---
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: aegisray-exit
  namespace: aegisray-prod
spec:
  replicas: 3
  selector:
    matchLabels:
      app: aegisray-exit
  template:
    metadata:
      labels:
        app: aegisray-exit
        version: v1.0.0
    spec:
      # Security context
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      
      containers:
      - name: aegisray
        image: aegisray/mesh:1.0.0
        imagePullPolicy: Always
        
        # Required capabilities for TUN interface
        securityContext:
          capabilities:
            add: ["NET_ADMIN"]
            drop: ["ALL"]
        
        # Environment configuration
        env:
        - name: AEGISRAY_NODE_TYPE
          value: "exit"
        - name: AEGISRAY_ENVIRONMENT  
          value: "production"
        - name: AEGISRAY_LOG_LEVEL
          value: "info"
        
        # Resource limits
        resources:
          limits:
            cpu: 2000m
            memory: 4Gi
          requests:
            cpu: 500m
            memory: 1Gi
        
        # Health checks
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 60
          periodSeconds: 30
        
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        
        # Port configuration
        ports:
        - containerPort: 443
          name: mesh
          protocol: TCP
        - containerPort: 8080
          name: api
          protocol: TCP
        
        # Volume mounts
        volumeMounts:
        - name: config
          mountPath: /etc/aegisray/config
          readOnly: true
        - name: certs
          mountPath: /etc/aegisray/certs
          readOnly: true
        - name: logs
          mountPath: /var/log/aegisray
      
      # Volumes
      volumes:
      - name: config
        configMap:
          name: aegisray-config
      - name: certs
        secret:
          secretName: aegisray-certs
      - name: logs
        emptyDir: {}

---
# k8s/service.yaml  
apiVersion: v1
kind: Service
metadata:
  name: aegisray-exit-service
  namespace: aegisray-prod
spec:
  type: LoadBalancer
  selector:
    app: aegisray-exit
  ports:
  - name: mesh
    port: 443
    targetPort: 443
    protocol: TCP
  - name: api
    port: 8080
    targetPort: 8080
    protocol: TCP

---
# k8s/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: aegisray-config
  namespace: aegisray-prod
data:
  node.yaml: |
    node_name: "k8s-exit-${HOSTNAME}"
    node_type: "exit"
    listen_port: 443
    
    network:
      name: "production"
      cidr: "100.64.0.0/16"
      
    security:
      use_tls: true
      stealth_mode: true
      
    performance:
      max_peers: 50
      
    logging:
      level: "info"
      file: "/var/log/aegisray/node.log"
```

---

## 🔒 Security Hardening

### System-Level Hardening

**OS Configuration:**
```bash
#!/bin/bash
# scripts/harden-system.sh

# Update system packages
apt update && apt upgrade -y

# Install security tools
apt install -y fail2ban ufw rkhunter chkrootkit

# Kernel hardening
cat >> /etc/sysctl.conf << 'EOF'
# Network security
net.ipv4.ip_forward = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1

# TCP hardening  
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 3

# Memory protection
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
EOF

sysctl -p

# Firewall configuration
ufw --force reset
ufw default deny incoming  
ufw default allow outgoing

# Allow AegisRay traffic
ufw allow 443/tcp comment 'AegisRay mesh'
ufw allow from 10.0.0.0/8 to any port 8080 comment 'AegisRay API internal'

# SSH hardening
sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart sshd

ufw --force enable
```

**Fail2Ban Configuration:**
```ini
# /etc/fail2ban/jail.local
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
backend = systemd

[aegisray-auth]
enabled = true
port = 443,8080
filter = aegisray-auth
logpath = /var/log/aegisray/auth.log
maxretry = 5

# /etc/fail2ban/filter.d/aegisray-auth.conf
[Definition]
failregex = authentication failed.*from <HOST>
            certificate validation failed.*from <HOST>
            invalid peer credentials.*from <HOST>
ignoreregex =
```

### Container Security

**Secure Docker Configuration:**
```yaml
# Secure container runtime
version: '3.8'
services:
  aegisray:
    # Use distroless base image
    image: aegisray/mesh:1.0.0-distroless
    
    # Security options
    security_opt:
      - no-new-privileges:true
      - seccomp:seccomp-profile.json
    
    # Read-only root filesystem
    read_only: true
    
    # Temporary filesystems for writable areas
    tmpfs:
      - /tmp:noexec,nosuid,size=100m
      - /var/run:noexec,nosuid,size=100m
    
    # User namespace
    user: "1000:1000"
    
    # Resource limits (prevent DoS)
    ulimits:
      nproc: 65535
      nofile:
        soft: 20000
        hard: 40000
        
    # Minimal capabilities
    cap_add:
      - NET_ADMIN     # Required for TUN
    cap_drop:
      - ALL
```

**Seccomp Profile:**
```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    {
      "names": [
        "read", "write", "open", "close", "stat", "fstat", "lstat", "poll",
        "lseek", "mmap", "mprotect", "munmap", "brk", "rt_sigaction",
        "rt_sigprocmask", "rt_sigreturn", "ioctl", "pread64", "pwrite64",
        "readv", "writev", "access", "pipe", "select", "sched_yield",
        "mremap", "msync", "mincore", "madvise", "shmget", "shmat", "shmctl",
        "dup", "dup2", "pause", "nanosleep", "getitimer", "alarm", "setitimer",
        "getpid", "sendfile", "socket", "connect", "accept", "sendto", "recvfrom",
        "sendmsg", "recvmsg", "shutdown", "bind", "listen", "getsockname",
        "getpeername", "socketpair", "setsockopt", "getsockopt", "clone",
        "fork", "vfork", "execve", "exit", "wait4", "kill", "uname", "semget",
        "semop", "semctl", "shmdt", "msgget", "msgsnd", "msgrcv", "msgctl",
        "fcntl", "flock", "fsync", "fdatasync", "truncate", "ftruncate",
        "getdents", "getcwd", "chdir", "fchdir", "rename", "mkdir", "rmdir",
        "creat", "link", "unlink", "symlink", "readlink", "chmod", "fchmod",
        "chown", "fchown", "lchown", "umask", "gettimeofday", "getrlimit",
        "getrusage", "sysinfo", "times", "ptrace", "getuid", "syslog", "getgid",
        "setuid", "setgid", "geteuid", "getegid", "setpgid", "getppid",
        "getpgrp", "setsid", "setreuid", "setregid", "getgroups", "setgroups",
        "setresuid", "getresuid", "setresgid", "getresgid", "getpgid",
        "setfsuid", "setfsgid", "getsid", "capget", "capset", "rt_sigpending",
        "rt_sigtimedwait", "rt_sigqueueinfo", "rt_sigsuspend", "sigaltstack",
        "utime", "mknod", "uselib", "personality", "ustat", "statfs", "fstatfs",
        "sysfs", "getpriority", "setpriority", "sched_setparam", "sched_getparam",
        "sched_setscheduler", "sched_getscheduler", "sched_get_priority_max",
        "sched_get_priority_min", "sched_rr_get_interval", "mlock", "munlock",
        "mlockall", "munlockall", "vhangup", "modify_ldt", "pivot_root",
        "_sysctl", "prctl", "arch_prctl", "adjtimex", "setrlimit", "chroot",
        "sync", "acct", "settimeofday", "mount", "umount2", "swapon", "swapoff",
        "reboot", "sethostname", "setdomainname", "iopl", "ioperm",
        "create_module", "init_module", "delete_module", "get_kernel_syms",
        "query_module", "quotactl", "nfsservctl", "getpmsg", "putpmsg",
        "afs_syscall", "tuxcall", "security", "gettid", "readahead", "setxattr",
        "lsetxattr", "fsetxattr", "getxattr", "lgetxattr", "fgetxattr",
        "listxattr", "llistxattr", "flistxattr", "removexattr", "lremovexattr",
        "fremovexattr", "tkill", "time", "futex", "sched_setaffinity",
        "sched_getaffinity", "set_thread_area", "io_setup", "io_destroy",
        "io_getevents", "io_submit", "io_cancel", "get_thread_area",
        "lookup_dcookie", "epoll_create", "epoll_ctl_old", "epoll_wait_old",
        "remap_file_pages", "getdents64", "set_tid_address", "restart_syscall",
        "semtimedop", "fadvise64", "timer_create", "timer_settime",
        "timer_gettime", "timer_getoverrun", "timer_delete", "clock_settime",
        "clock_gettime", "clock_getres", "clock_nanosleep", "exit_group",
        "epoll_wait", "epoll_ctl", "tgkill", "utimes", "vserver", "mbind",
        "set_mempolicy", "get_mempolicy", "mq_open", "mq_unlink", "mq_timedsend",
        "mq_timedreceive", "mq_notify", "mq_getsetattr", "kexec_load", "waitid",
        "add_key", "request_key", "keyctl", "ioprio_set", "ioprio_get", "inotify_init",
        "inotify_add_watch", "inotify_rm_watch", "migrate_pages", "openat",
        "mkdirat", "mknodat", "fchownat", "futimesat", "newfstatat", "unlinkat",
        "renameat", "linkat", "symlinkat", "readlinkat", "fchmodat", "faccessat",
        "pselect6", "ppoll", "unshare", "set_robust_list", "get_robust_list",
        "splice", "tee", "sync_file_range", "vmsplice", "move_pages", "utimensat",
        "epoll_pwait", "signalfd", "timerfd_create", "eventfd", "fallocate",
        "timerfd_settime", "timerfd_gettime", "accept4", "signalfd4", "eventfd2",
        "epoll_create1", "dup3", "pipe2", "inotify_init1", "preadv", "pwritev",
        "rt_tgsigqueueinfo", "perf_event_open", "recvmmsg", "fanotify_init",
        "fanotify_mark", "prlimit64", "name_to_handle_at", "open_by_handle_at",
        "clock_adjtime", "syncfs", "sendmmsg", "setns", "getcpu", "process_vm_readv",
        "process_vm_writev", "kcmp", "finit_module", "sched_setattr", "sched_getattr",
        "renameat2", "seccomp", "getrandom", "memfd_create", "kexec_file_load",
        "bpf", "execveat", "userfaultfd", "membarrier", "mlock2", "copy_file_range",
        "preadv2", "pwritev2"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

---

## ⚖️ High Availability Setup

### Load Balancing

**HAProxy Configuration:**
```
# /etc/haproxy/haproxy.cfg
global
    daemon
    maxconn 4096
    log stdout local0
    
    # SSL/TLS configuration
    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets
    ssl-default-bind-ciphers ECDHE+aRSA+AES256+GCM+SHA384:ECDHE+aRSA+CHACHA20:ECDHE+aRSA+AES128+GCM+SHA256
    
defaults
    mode tcp
    timeout connect 10s
    timeout client 60s
    timeout server 60s
    option tcplog
    log global

# AegisRay mesh traffic balancing
frontend aegis_mesh_frontend
    bind *:443
    mode tcp
    option tcplog
    
    # Health checks
    tcp-request inspect-delay 5s
    tcp-request content accept if { req.ssl_hello_type 1 }
    
    default_backend aegis_mesh_backend

backend aegis_mesh_backend
    mode tcp
    balance roundrobin
    option tcp-check
    
    # Health check via HTTP API
    tcp-check connect port 8080
    tcp-check send "GET /health HTTP/1.0\r\n\r\n"
    tcp-check expect string "healthy"
    
    # Backend servers
    server aegis1 10.0.1.10:443 check port 8080 inter 30s fall 3 rise 2
    server aegis2 10.0.1.11:443 check port 8080 inter 30s fall 3 rise 2 
    server aegis3 10.0.1.12:443 check port 8080 inter 30s fall 3 rise 2

# Management API (internal only)
frontend aegis_api_frontend
    bind 127.0.0.1:8080
    mode http
    option httplog
    default_backend aegis_api_backend
    
backend aegis_api_backend
    mode http
    balance roundrobin
    option httpchk GET /health
    
    server aegis1 10.0.1.10:8080 check inter 10s
    server aegis2 10.0.1.11:8080 check inter 10s
    server aegis3 10.0.1.12:8080 check inter 10s
```

### Database High Availability

**PostgreSQL Cluster (for configuration/state):**
```yaml
# docker-compose.ha.yml
version: '3.8'

services:
  postgres-primary:
    image: postgres:13
    environment:
      - POSTGRES_DB=aegisray
      - POSTGRES_USER=aegisray
      - POSTGRES_PASSWORD=${DB_PASSWORD}
      - POSTGRES_REPLICATION_USER=replicator
      - POSTGRES_REPLICATION_PASSWORD=${REPL_PASSWORD}
    volumes:
      - postgres-primary:/var/lib/postgresql/data
      - ./scripts/setup-replication.sh:/docker-entrypoint-initdb.d/setup-replication.sh
    command: |
      postgres -c wal_level=replica 
               -c max_wal_senders=3 
               -c max_replication_slots=3
               -c synchronous_commit=on
               -c synchronous_standby_names='standby1'
    networks:
      - aegis-db
      
  postgres-standby:
    image: postgres:13  
    environment:
      - PGUSER=postgres
      - POSTGRES_PASSWORD=${DB_PASSWORD}
      - POSTGRES_PRIMARY_USER=replicator
      - POSTGRES_PRIMARY_PASSWORD=${REPL_PASSWORD}
      - POSTGRES_PRIMARY_HOST=postgres-primary
    volumes:
      - postgres-standby:/var/lib/postgresql/data
    depends_on:
      - postgres-primary
    command: |
      bash -c "
      if [ ! -f /var/lib/postgresql/data/PG_VERSION ]; then
        pg_basebackup -h postgres-primary -D /var/lib/postgresql/data -U replicator -v -P -W
        echo 'standby_mode = on' >> /var/lib/postgresql/data/recovery.conf
        echo 'primary_conninfo = ''host=postgres-primary port=5432 user=replicator''' >> /var/lib/postgresql/data/recovery.conf
      fi
      postgres
      "

networks:
  aegis-db:
    driver: bridge

volumes:
  postgres-primary:
  postgres-standby:
```

### Disaster Recovery

**Backup Strategy:**
```bash
#!/bin/bash
# scripts/backup.sh

BACKUP_DIR="/opt/backups/aegisray"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p "${BACKUP_DIR}/${DATE}"

# Backup configuration
tar -czf "${BACKUP_DIR}/${DATE}/config.tar.gz" /etc/aegisray/

# Backup certificates (encrypted)
gpg --cipher-algo AES256 --compress-algo 2 --cert-digest-algo SHA512 \
    --symmetric --output "${BACKUP_DIR}/${DATE}/certs.gpg" \
    --batch --yes --passphrase "${BACKUP_PASSPHRASE}" \
    /etc/aegisray/certs/

# Backup database
pg_dump -h localhost -U aegisray -d aegisray | \
    gzip > "${BACKUP_DIR}/${DATE}/database.sql.gz"

# Backup logs (last 7 days)
find /var/log/aegisray -name "*.log" -mtime -7 -exec \
    tar -czf "${BACKUP_DIR}/${DATE}/logs.tar.gz" {} +

# Upload to S3 (encrypted)
aws s3 cp "${BACKUP_DIR}/${DATE}" \
    "s3://aegisray-backups/$(hostname)/${DATE}/" \
    --recursive --sse AES256

# Cleanup old local backups (keep 30 days)
find "${BACKUP_DIR}" -type d -mtime +30 -exec rm -rf {} +

echo "Backup completed: ${DATE}"
```

**Recovery Procedure:**
```bash
#!/bin/bash
# scripts/restore.sh

RESTORE_DATE="$1"
BACKUP_DIR="/opt/backups/aegisray"

if [ -z "$RESTORE_DATE" ]; then
    echo "Usage: $0 <backup_date>"
    exit 1
fi

# Stop AegisRay service
systemctl stop aegisray

# Download backup from S3
aws s3 cp "s3://aegisray-backups/$(hostname)/${RESTORE_DATE}/" \
    "${BACKUP_DIR}/${RESTORE_DATE}/" --recursive

# Restore configuration
tar -xzf "${BACKUP_DIR}/${RESTORE_DATE}/config.tar.gz" -C /

# Restore certificates
gpg --decrypt --batch --yes \
    --passphrase "${BACKUP_PASSPHRASE}" \
    "${BACKUP_DIR}/${RESTORE_DATE}/certs.gpg" | \
    tar -xz -C /etc/aegisray/

# Restore database
dropdb -U postgres aegisray
createdb -U postgres aegisray
gunzip -c "${BACKUP_DIR}/${RESTORE_DATE}/database.sql.gz" | \
    psql -U postgres -d aegisray

# Set permissions
chown -R aegisray:aegisray /etc/aegisray/
chmod 600 /etc/aegisray/certs/*.key
chmod 644 /etc/aegisray/certs/*.crt

# Start service
systemctl start aegisray

echo "Restore completed from: ${RESTORE_DATE}"
```

---

## 📊 Monitoring & Alerting

### Prometheus Configuration

**prometheus.yml:**
```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "aegisray-rules.yml"

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093

scrape_configs:
  # AegisRay node metrics
  - job_name: 'aegisray'
    static_configs:
      - targets:
        - 'aegis-exit-1:8080'
        - 'aegis-exit-2:8080'
        - 'aegis-relay-1:8080'
    scrape_interval: 30s
    metrics_path: '/metrics'
    
  # System metrics
  - job_name: 'node-exporter'
    static_configs:
      - targets:
        - 'aegis-exit-1:9100'
        - 'aegis-exit-2:9100'
        - 'aegis-relay-1:9100'
```

**Alert Rules:**
```yaml
# aegisray-rules.yml
groups:
- name: aegisray
  rules:
  
  # Node health alerts
  - alert: AegisRayNodeDown
    expr: up{job="aegisray"} == 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "AegisRay node is down"
      description: "AegisRay node {{ $labels.instance }} has been down for more than 1 minute"
  
  # Peer connectivity alerts
  - alert: LowPeerCount
    expr: aegisray_connected_peers < 2
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "Low peer count on AegisRay node"
      description: "Node {{ $labels.instance }} has only {{ $value }} connected peers"
  
  # Traffic alerts
  - alert: HighPacketLoss
    expr: rate(aegisray_packets_dropped_total[5m]) > 0.01
    for: 2m
    labels:
      severity: warning
    annotations:
      summary: "High packet loss detected"
      description: "Packet loss rate is {{ $value | humanizePercentage }} on {{ $labels.instance }}"
  
  # Security alerts
  - alert: AuthenticationFailures
    expr: rate(aegisray_auth_failures_total[5m]) > 10
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "High authentication failure rate"
      description: "Authentication failures at {{ $value }} per second on {{ $labels.instance }}"
  
  # System resource alerts
  - alert: HighCPUUsage
    expr: 100 - (avg by(instance) (irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) > 80
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High CPU usage"
      description: "CPU usage is {{ $value }}% on {{ $labels.instance }}"
  
  - alert: HighMemoryUsage
    expr: (node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes > 0.9
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: "High memory usage"
      description: "Memory usage is {{ $value | humanizePercentage }} on {{ $labels.instance }}"
```

### Grafana Dashboard

**AegisRay Dashboard JSON:**
```json
{
  "dashboard": {
    "title": "AegisRay Mesh Network",
    "panels": [
      {
        "title": "Node Status",
        "type": "stat",
        "targets": [
          {
            "expr": "up{job=\"aegisray\"}",
            "legendFormat": "{{instance}}"
          }
        ]
      },
      {
        "title": "Connected Peers",
        "type": "graph", 
        "targets": [
          {
            "expr": "aegisray_connected_peers",
            "legendFormat": "{{instance}}"
          }
        ]
      },
      {
        "title": "Traffic Volume",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(aegisray_bytes_sent_total[5m])",
            "legendFormat": "Sent - {{instance}}"
          },
          {
            "expr": "rate(aegisray_bytes_received_total[5m])",
            "legendFormat": "Received - {{instance}}"
          }
        ]
      },
      {
        "title": "Latency Distribution",
        "type": "heatmap",
        "targets": [
          {
            "expr": "aegisray_peer_latency_seconds",
            "legendFormat": "{{peer_id}}"
          }
        ]
      }
    ]
  }
}
```

### Log Management

**ELK Stack Configuration:**
```yaml
# docker-compose.logging.yml
version: '3.8'

services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.15.0
    environment:
      - node.name=elasticsearch
      - cluster.name=aegisray-logs
      - discovery.type=single-node
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
    volumes:
      - elasticsearch-data:/usr/share/elasticsearch/data
    ports:
      - "9200:9200"
      
  logstash:
    image: docker.elastic.co/logstash/logstash:7.15.0
    volumes:
      - ./logstash/pipeline:/usr/share/logstash/pipeline
      - ./logstash/config:/usr/share/logstash/config
    ports:
      - "5044:5044"
    depends_on:
      - elasticsearch
      
  kibana:
    image: docker.elastic.co/kibana/kibana:7.15.0
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
    ports:
      - "5601:5601"
    depends_on:
      - elasticsearch
      
  filebeat:
    image: docker.elastic.co/beats/filebeat:7.15.0
    user: root
    volumes:
      - ./filebeat/filebeat.yml:/usr/share/filebeat/filebeat.yml:ro
      - /var/log/aegisray:/var/log/aegisray:ro
      - /var/lib/docker/containers:/var/lib/docker/containers:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro
    command: ["--strict.perms=false"]
    depends_on:
      - logstash

volumes:
  elasticsearch-data:
```

---

This production deployment guide provides a comprehensive foundation for deploying AegisRay in enterprise environments with proper security, monitoring, and operational practices.
