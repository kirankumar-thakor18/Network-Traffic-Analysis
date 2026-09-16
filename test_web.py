import app

client = app.app.test_client()

resp = client.get("/")
html = resp.data.decode("utf-8")
checks = {
    "Title": "<title>Network Traffic Analyzer</title>" in html,
    "Upload form": 'action="/analyze"' in html,
    "Drag-drop zone": "dropZone" in html,
    "Features": "Threat Detection" in html,
}
for name, ok in checks.items():
    print(f"{name}: {'OK' if ok else 'FAIL'}")

if all(checks.values()):
    print("All homepage checks passed!")
else:
    print("Some checks FAILED!")