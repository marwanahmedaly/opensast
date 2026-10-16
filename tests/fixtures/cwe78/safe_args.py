import subprocess

def run(request):
    return subprocess.run(["ping", "--", request.args["host"]], shell=False)
