#!/bin/python3

import json

from django.core.exceptions import ValidationError
from django.core.validators import URLValidator


def urls():
    f = open("report.json")
    data = json.load(f)
    urls = []
    """for i in data:
        # print(i)
        # print("--------------")"""

    """for j in data[i]:
        print(j)"""
    for j in data["strings"]:
        validate = URLValidator()
        try:
            validate(j)
            urls.append(j)
        except ValidationError as exception:
            continue
    print("Found " + str(len(urls)) + " URLs in this file.")
    for y in urls:
        print(y)
    f.close()
    return urls


def signatures():
    signature = []
    f = open("report.json")
    data = json.load(f)
    for j in data["signatures"]:
        # print("File " + str(j['description']))
        signature.append(j['description'])
        # print(j['marks'])

        for x in j["marks"]:
            if j[
                'description'] != "Checks for the Locally Unique Identifier on the system for a suspicious privilege" and \
                    j['description'] != "Allocates read-write-execute memory (usually to unpack itself)" and j[
                'description'] != "Queries for potentially installed applications" and j[
                'description'] != "Collects information about installed applications":
                # print(x)
                try:
                    # print(x['category'])
                    # print(x['ioc'])
                    signature.append(x['ioc'])
                except KeyError:
                    continue
        signature.append("##########")
        # print("##########")
        """for k in data[j]:
            print(k)"""
    for y in signature:
        print(y)
    # Closing file
    f.close()
    return signature


