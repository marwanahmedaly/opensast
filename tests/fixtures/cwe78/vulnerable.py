import os

def run(request):
    return os.system("ping " + request.args["host"])
