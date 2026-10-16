def search(request, db):
    query = request.args["q"]
    return db.execute("SELECT * FROM users WHERE name=?", (query,))
