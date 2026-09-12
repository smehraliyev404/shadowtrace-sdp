# ShadowTrace: shared MongoDB connection helper
# Supports two modes, selected purely by which env vars are set in .env:
#   1. Shared team cluster (MongoDB Atlas) -> set MONGO_URI to the full
#      mongodb+srv://... connection string from Atlas.
#   2. Local/dev single-node Mongo (docker-compose) -> set MONGO_USERNAME,
#      MONGO_PASSWORD, MONGO_HOST (defaults to localhost:27017).
# MONGO_DATABASE is required in both modes so every script points at the
# same logical database regardless of where it physically lives.

import os

from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv()


def get_client() -> MongoClient:
    uri = os.getenv("MONGO_URI")
    if uri:
        return MongoClient(uri, serverSelectionTimeoutMS=5000)

    username = os.getenv("MONGO_USERNAME")
    password = os.getenv("MONGO_PASSWORD")
    if not username or not password:
        raise RuntimeError(
            "Set MONGO_URI (shared Atlas cluster) or MONGO_USERNAME + "
            "MONGO_PASSWORD (local docker-compose Mongo) in .env"
        )

    host = os.getenv("MONGO_HOST", "localhost:27017")
    return MongoClient(
        f"mongodb://{host}",
        username=username,
        password=password,
        authSource="admin",
        serverSelectionTimeoutMS=5000,
    )


def get_database():
    database_name = os.getenv("MONGO_DATABASE")
    if not database_name:
        raise RuntimeError("MONGO_DATABASE is missing from the .env file")
    return get_client()[database_name]
