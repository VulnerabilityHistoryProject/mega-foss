import pymongo

def read_config(path='settings.ini'):
    cfg = {}
    with open(path) as file:
        for line in file:
            line = line.strip()
            if '=' in line:
                key, value = line.split('=', 1)
                cfg[key] = value.strip().strip('"')
    return cfg

def mg_connect(cfg):
    host = cfg.get('HOST')
    port = cfg.get('PORT')
    database_name = cfg.get('DATABASE')

    link = host if host.startswith('mongodb://') else f"mongodb://{host}:{port}/"
    client = pymongo.MongoClient(link)
    database = client[database_name]
    return database
