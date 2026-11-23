import pickle
import os

def save_package(filepath: str, data: dict):
    """Saves the encrypted package to a pickle file."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, 'wb') as f:
        pickle.dump(data, f)

def load_package(filepath: str) -> dict:
    """Loads the encrypted package from a pickle file."""
    if not os.path.exists(filepath):
        return None
    with open(filepath, 'rb') as f:
        return pickle.load(f)
