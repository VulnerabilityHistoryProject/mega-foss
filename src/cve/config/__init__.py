import os
import configparser
import pymongo

def mg_connect():
    config = configparser.ConfigParser()
    config.read(os.path.join(os.path.dirname(__file__), 'mongo.ini'))

    host = config['DEFAULT']['HOST']
    port = config['DEFAULT']['PORT']
    database = config['DEFAULT']['DATABASE']

    if host in ["localhost", "127.0.0.1"]:
        link = f"mongodb://127.0.0.1:{port}/"
    elif host.startswith("mongodb://"):
        link = host
    else:
        link = f"mongodb://{host}:{port}/"

    client = pymongo.MongoClient(link)

    return client[database]
