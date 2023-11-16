import shelve

class ObjectStore:
    prefix = "/peers/"
    db = None

    def __init__(self, fname="object.store"):
        self.db = shelve.open(f"{self.prefix}{fname}")
        pass

    def close(self):
        self.db.close()

    def store_object(self, key, value):
        self.db[key] = value

    def get_object(self, key):
        if key in self.db:
            return self.db[key]
        return None