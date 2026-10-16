def search(request, db):
    query = request.args["q"]
    sql = "SELECT * FROM users WHERE name='" + query + "'"
    return db.execute(sql)
