import sqlite3 as lite

con = lite.connect('sites.db')

with con:

    cur = con.cursor()

    cur.execute("CREATE TABLE url_safety_data(url TEXT, safety TEXT, total_votes TEXT, categories TEXT, updated LONG)")
    cur.execute("CREATE INDEX utl_index ON url_safety_data(url);")
    cur.execute("CREATE TABLE url_safety_data_requests(url TEXT, time LONG)")

    con.commit()