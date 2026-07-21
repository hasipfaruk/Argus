import hashlib
import subprocess


def run(cmd):
    subprocess.run(cmd, shell=True)


def digest(password):
    return hashlib.md5(password.encode()).hexdigest()
