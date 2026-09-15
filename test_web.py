import app

client = app.app.test_client()

resp = client.get("/")
html = resp.data.decode("utf-8")
checks = {
    "Title": "<title>Network Traffic Analyzer</title>" in html,
    "Upload form": 'action="/analyze"' in html,
    "Drag-drop zone": "dropZone" in html,
    "Demo button": "Run Demo" in html,
    "Features": "Threat Detection" in html,
}
for name, ok in checks.items():
    print(f"{name}: {'OK' if ok else 'FAIL'}")

if all(checks.values()):
    print("All homepage checks passed!")
else:
    print("Some checks FAILED!")

resp = client.get("/demo")
html = resp.data.decode("utf-8")
dash_checks = {
    "Total Packets stat": "Total Packets" in html,
    "Protocol chart": "data:image/png;base64" in html,
    "Alerts section": "Threat Alerts" in html,
    "Source IPs table": "Top Source IPs" in html,
    "Ports table": "Top Destination Ports" in html,
}
for name, ok in dash_checks.items():
    print(f"[Dashboard] {name}: {'OK' if ok else 'FAIL'}")

if all(dash_checks.values()):
    print("All dashboard checks passed!")
else:
    print("Some dashboard checks FAILED!")