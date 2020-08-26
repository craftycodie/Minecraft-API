import os
import json

versions = []

def load_versions():
    global versions
    for subdir, dirs, files in os.walk('./public/versions/'):
        for file in files:
            openFile = open(os.path.join(subdir, file))
            versions.append(json.load(openFile))

    return versions

def get_versions():
    global versions
    return versions