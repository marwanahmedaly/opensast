import os

def download(request):
    return open("/srv/files/" + request.args["name"]).read()
