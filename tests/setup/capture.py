"""Read-only: saves real Proxmox API answers as test data for the setup file's stand-in commands.
Run as user maintool on the tool container. The data stays in the test folder and is deleted afterwards.
Node addresses are moved to a fixed test network first (see neutral), so the tests work on any cluster."""
import json
import os
import sys

for line in open("/etc/maintool/maintool.env", encoding="utf-8"):
    line = line.strip()
    if line and not line.startswith("#") and "=" in line:
        k, v = line.split("=", 1)
        os.environ[k.strip()] = v.strip()
sys.path.insert(0, "/opt/maintool/app")
import main  # noqa: E402

out = sys.argv[1]
TEST_NET = "192.168.30"


def neutral(data):
    """Moves the node addresses and the node's own bridge to the test network 192.168.30.0/24 (nodes .1, .2, ...;
    router .254), so the tests expect the same addresses on every cluster and hold none of the own network."""
    nodes = sorted((e for e in data["status"] if e.get("type") == "node"), key=lambda e: (e.get("nodeid") or 0, e["name"]))
    old = next((e.get("ip") for e in nodes if e.get("local")), None)
    for i, e in enumerate(nodes, 1):
        e["ip"] = f"{TEST_NET}.{i}"
    new = next(e["ip"] for e in nodes if e.get("local"))
    for b in data["bridges"]:
        if old and (b.get("address") or (b.get("cidr") or "").split("/")[0]) == old:
            b.update(address=new, cidr=f"{new}/24", netmask="24", gateway=f"{TEST_NET}.254")


def f(api):
    status = api.cluster.status.get()
    node = next(e["name"] for e in status if e.get("type") == "node" and e.get("local"))
    tmpl = [s for s in api.nodes(node).storage.get(content="vztmpl")]
    data = {
        "version": api.version.get(), "status": status, "guests": api.cluster.resources.get(type="vm"),
        "ha": api.cluster.ha.resources.get(), "disks": api.nodes(node).storage.get(content="rootdir"),
        "tmplstores": tmpl, "tmplcontent": api.nodes(node).storage("local").content.get(content="vztmpl"),
        "aplinfo": api.nodes(node).aplinfo.get(), "bridges": api.nodes(node).network.get(type="any_bridge"),
        "time": api.nodes(node).time.get(), "user": api.access.users("maintool@pve").get(),
        "tokens": api.access.users("maintool@pve").token.get(),
    }
    neutral(data)
    for name, value in data.items():
        json.dump(value, open(f"{out}/{name}.json", "w"))
    deb = sorted(a["template"] for a in data["aplinfo"] if a.get("section") == "system" and a["template"].startswith("debian-1"))
    print("lokale node:", node, "| Debian-sjablonen in de lijst:", deb)
    print("aanwezig op local:", [c["volid"] for c in data["tmplcontent"]])

main.pve.run(f)
