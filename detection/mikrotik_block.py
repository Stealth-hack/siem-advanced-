import routeros_api

MIKROTIK_HOST = "192.168.88.1"  # default MikroTik IP, change to actual
MIKROTIK_USER = "admin"
MIKROTIK_PASSWORD = ""  # change to actual password
BLOCK_DURATION = "01:00:00"  # block for 1 hour

def block_ip(ip, reason="SIEM Auto-Block"):
    try:
        connection = routeros_api.RouterOsApiPool(
            MIKROTIK_HOST,
            username=MIKROTIK_USER,
            password=MIKROTIK_PASSWORD,
            plaintext_login=True
        )
        api = connection.get_api()

        firewall = api.get_resource('/ip/firewall/address-list')
        firewall.add(
            list="blacklist",
            address=ip,
            comment=reason,
            timeout=BLOCK_DURATION
        )
        connection.disconnect()
        print(f"[+] Blocked {ip} on MikroTik for {BLOCK_DURATION}")
        return True

    except Exception as e:
        print(f"[!] Failed to block {ip} on MikroTik: {e}")
        return False

def unblock_ip(ip):
    try:
        connection = routeros_api.RouterOsApiPool(
            MIKROTIK_HOST,
            username=MIKROTIK_USER,
            password=MIKROTIK_PASSWORD,
            plaintext_login=True
        )
        api = connection.get_api()

        firewall = api.get_resource('/ip/firewall/address-list')
        entries = firewall.get(list="blacklist", address=ip)
        for entry in entries:
            firewall.remove(id=entry['id'])

        connection.disconnect()
        print(f"[+] Unblocked {ip} on MikroTik")
        return True

    except Exception as e:
        print(f"[!] Failed to unblock {ip}: {e}")
        return False
