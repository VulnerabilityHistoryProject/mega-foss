import pymongo

def mg_connect():
    cfg = {}
    with open('settings.ini') as file:
        for line in file:
            line = line.strip()
            if '=' in line:
                key, value = line.split('=', 1)
                cfg[key] = value.strip().strip('"')

    host = cfg.get('HOST')
    port = cfg.get('PORT')
    database_name = cfg.get('DATABASE')

    link = host if host.startswith('mongodb://') else f"mongodb://{host}:{port}/"
    client = pymongo.MongoClient(link)
    database = client[database_name]

    return database, cfg
