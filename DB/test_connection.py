from mongo_client import get_client, get_database

client = get_client()

try:
    client.admin.command("ping")
    database = get_database()

    print("MongoDB connection successful")
    print(f"Database selected: {database.name}")
    print(f"Collections present: {database.list_collection_names()}")
finally:
    client.close()
