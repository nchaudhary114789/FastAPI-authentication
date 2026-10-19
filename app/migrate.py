import importlib
from pymongo import MongoClient
from .auth import settings

MIGRATIONS = [
   "app.migrations.001_initial_indexes",
   "app.migrations.002_username_unique_index"
]

def get_database():
   client = MongoClient(settings.MONGODB_URL)
   return client[settings.MONGODB_DATABASE]

def run_migrations():
   db = get_database()
   migrations_collection = db["schema_migrations"]
   applied_migrations = {
       migration["version"]
       for migration in migrations_collection.find(
           {},
           {"version": 1}
       )
   }
   for migration_path in MIGRATIONS:
       module = importlib.import_module(migration_path)
       version = migration_path.split(".")[-1].split("_")[0]
       if version in applied_migrations:
           print(f"✓ Migration {version} already applied")
           continue
       print(f"→ Applying migration {version}...")
       try:
           module.up(db)
           migrations_collection.update_one(
               {"version": version},
               {
                   "$set": {
                       "version": version,
                       "name": migration_path
                   }
               },
               upsert=True
           )
           print(f"✓ Migration {version} applied successfully")
       except Exception as error:
           print(f"✗ Migration {version} failed")
           print(f"Error: {error}")
           raise
   print("\nAll migrations are up to date.")

if __name__ == "__main__":
   run_migrations()