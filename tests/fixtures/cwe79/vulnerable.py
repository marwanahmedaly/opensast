from flask import request
from markupsafe import Markup

def page():
    return Markup("<p>" + request.args["name"] + "</p>")
