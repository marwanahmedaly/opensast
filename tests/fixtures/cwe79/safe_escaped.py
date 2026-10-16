from flask import escape, request

def page():
    return "<p>" + escape(request.args["name"]) + "</p>"
