import json
import os

def save_json(data, filename):
    os.makedirs("output", exist_ok=True)
    path = f"output/{filename}"

    with open(path, "w") as f:
        json.dump(data, f, indent=4)

    return path
