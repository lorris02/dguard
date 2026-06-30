import os
import platform
import subprocess
import sys

CERT_PATH = os.path.expanduser(os.path.join("~", ".mitmproxy", "mitmproxy-ca-cert.pem"))


def install_certificate() -> None:
    if not os.path.exists(CERT_PATH):
        print("Certificate not found. Run the agent once first to generate it, then re-run --install-cert.")
        sys.exit(1)

    system = platform.system()
    print(f"Installing DGuard root certificate on {system}...")

    if system == "Windows":
        subprocess.run(["certutil", "-addstore", "-f", "ROOT", CERT_PATH], check=True)
    elif system == "Darwin":
        subprocess.run(
            ["sudo", "security", "add-trusted-cert", "-d", "-r", "trustRoot",
             "-k", "/Library/Keychains/System.keychain", CERT_PATH],
            check=True,
        )
    elif system == "Linux":
        dest = "/usr/local/share/ca-certificates/dguard-mitmproxy.crt"
        subprocess.run(["sudo", "cp", CERT_PATH, dest], check=True)
        subprocess.run(["sudo", "update-ca-certificates"], check=True)
    else:
        print(f"Unsupported platform: {system}. Install {CERT_PATH} manually as a trusted root CA.")
        sys.exit(1)

    print("Certificate installed. Browsers and apps will now trust the DGuard proxy.")


def set_system_proxy(port: int) -> None:
    system = platform.system()
    proxy = f"127.0.0.1:{port}"

    if system == "Windows":
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            0, winreg.KEY_WRITE,
        )
        winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, proxy)
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
        winreg.CloseKey(key)

    elif system == "Darwin":
        for service in _get_mac_network_services():
            subprocess.run(["sudo", "networksetup", "-setwebproxy", service, "127.0.0.1", str(port)], check=False)
            subprocess.run(["sudo", "networksetup", "-setsecurewebproxy", service, "127.0.0.1", str(port)], check=False)

    elif system == "Linux":
        print(f"Linux detected. Set your system proxy to {proxy} via Settings > Network > Proxy.")
        return

    print(f"System proxy set to {proxy}")


def unset_system_proxy() -> None:
    system = platform.system()

    if system == "Windows":
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            0, winreg.KEY_WRITE,
        )
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
        winreg.CloseKey(key)

    elif system == "Darwin":
        for service in _get_mac_network_services():
            subprocess.run(["sudo", "networksetup", "-setwebproxystate", service, "off"], check=False)
            subprocess.run(["sudo", "networksetup", "-setsecurewebproxystate", service, "off"], check=False)

    print("System proxy restored.")


def _get_mac_network_services() -> list[str]:
    try:
        out = subprocess.check_output(["networksetup", "-listallnetworkservices"], text=True)
        return [line.strip() for line in out.splitlines() if line.strip() and not line.startswith("*") and line != "An asterisk (*)..."]
    except Exception:
        return ["Wi-Fi", "Ethernet"]
