"""Intentionally vulnerable path-traversal/secret/deserialization fixture."""

import hashlib
import os
import pickle
import yaml


# Deliberately fake values for scanner testing only.
DATABASE_PASSWORD = "DEMO_PASSWORD_DO_NOT_USE"
API_KEY = "DEMO_API_KEY_DO_NOT_USE"
JWT_SECRET = "DEMO_JWT_SECRET_DO_NOT_USE"


def read_file_vulnerable(filename):
    base_dir = "/var/www/uploads/"
    filepath = base_dir + filename
    with open(filepath, "r") as handle:
        return handle.read()


def read_file_secure(filename):
    base_dir = "/var/www/uploads/"
    filepath = os.path.realpath(os.path.join(base_dir, filename))
    if os.path.commonpath([base_dir, filepath]) != os.path.realpath(base_dir):
        raise ValueError("Access denied")
    with open(filepath, "r") as handle:
        return handle.read()


def hash_password_vulnerable(password):
    return hashlib.md5(password.encode()).hexdigest()


def load_user_session_vulnerable(session_data):
    return pickle.loads(session_data)


def parse_config_vulnerable(yaml_content):
    return yaml.load(yaml_content)


def parse_config_secure(yaml_content):
    return yaml.safe_load(yaml_content)
