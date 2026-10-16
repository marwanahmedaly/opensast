from pathlib import Path

def download(request):
    base = Path("/srv/files").resolve()
    target = (base / request.args["name"]).resolve()
    if base not in target.parents:
        raise ValueError("invalid path")
    return target.read_text()
