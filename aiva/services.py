"""Classify a finding into a human service/product label from its name.

Deterministic keyword matching — order matters (most specific first), so
'openssh' wins over 'ssh', 'tomcat' over 'apache', etc.
"""
from __future__ import annotations

_RULES = [
    ("unrealircd", "UnrealIRCd (IRC)"),
    ("tomcat", "Apache Tomcat"),
    ("samba", "Samba / SMB"),
    ("badlock", "Samba / SMB"),
    ("isc bind", "ISC BIND (DNS)"),
    ("bind", "ISC BIND (DNS)"),
    ("openssh", "OpenSSH"),
    ("openssl", "OpenSSL"),
    ("heartbleed", "OpenSSL"),
    ("postfix", "Postfix (SMTP)"),
    ("smtp", "SMTP"),
    ("php-fpm", "PHP-FPM"),
    ("php", "PHP"),
    ("drupal", "Drupal"),
    ("struts", "Apache Struts"),
    ("apache", "Apache HTTP"),
    ("vsftpd", "vsftpd (FTP)"),
    ("ftp", "FTP"),
    ("mysql", "MySQL"),
    ("postgresql", "PostgreSQL"),
    ("distcc", "DistCC"),
    ("twiki", "TWiki"),
    ("tikiwiki", "Tiki Wiki"),
    ("tiki wiki", "Tiki Wiki"),
    ("java rmi", "Java RMI"),
    ("rmi", "Java RMI"),
    ("vnc", "VNC"),
    ("rsh", "rsh (remote shell)"),
    ("rlogin", "rlogin"),
    ("telnet", "Telnet"),
    ("netlogon", "Windows Netlogon"),
    ("smbv1", "SMB"),
    ("smb signing", "SMB"),
    ("smb", "SMB"),
    ("rdp", "RDP"),
    ("dns", "DNS"),
    ("http trace", "HTTP / Web"),
    ("http", "HTTP / Web"),
    ("ssl", "SSL / TLS"),
    ("tls", "SSL / TLS"),
    ("ssh", "SSH"),
    ("nfs", "NFS"),
    ("x server", "X11"),
    ("icmp", "ICMP"),
]


def classify_service(name: str) -> str:
    n = (name or "").lower()
    for kw, label in _RULES:
        if kw in n:
            return label
    return "—"
