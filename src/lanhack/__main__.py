import os, sys, subprocess

from lanhack import config
from lanhack.app import NetcutApp

def main():
    try:
        app = NetcutApp()
        app.run()
    except KeyboardInterrupt:
        pass
    finally:
        config.quit_flag = True
        if config.quick_tc_qdisc:
            subprocess.run(["tc", "qdisc", "del", "dev", config.iface, "root"], stderr=subprocess.DEVNULL)
        print("\n[+] Cleaned up.")

if __name__ == "__main__":
    main()
