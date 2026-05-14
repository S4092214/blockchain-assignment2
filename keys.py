"""
Hardcoded cryptographic parameters from the A2 List of Keys document.
No third-party cryptography libraries are used.
"""

PART1_KEYS = {
    "A": {
        "p": 1210613765735147311106936311866593978079938707,
        "q": 1247842850282035753615951347964437248190231863,
        "e": 815459040813953176289801,
    },
    "B": {
        "p": 787435686772982288169641922308628444877260947,
        "q": 1325305233886096053310340418467385397239375379,
        "e": 692450682143089563609787,
    },
    "C": {
        "p": 1014247300991039444864201518275018240361205111,
        "q": 904030450302158058469475048755214591704639633,
        "e": 1158749422015035388438057,
    },
    "D": {
        "p": 1287737200891425621338551020762858710281638317,
        "q": 1330909125725073469794953234151525201084537607,
        "e": 33981230465225879849295979,
    },
}

PART2_KEYS = {
    "PKG": {
        "p": 61,
        "q": 53,
        "e": 17
    },

    "USER": {
        "p": 47,
        "q": 59,
        "e": 17
    }
}

PKG_KEY = {
    "p": 1004162036461488639338597000466705179253226703,
    "q": 950133741151267522116252385927940618264103623,
    "e": 973028207197278907211,
}

PROCUREMENT_OFFICER_KEY = {
    "p": 1080954735722463992988394149602856332100628417,
    "q": 1158106283320086444890911863299879973542293243,
    "e": 106506253943651610547613,
}

INVENTORY_IDENTITIES = {
    "A": 126,
    "B": 127,
    "C": 128,
    "D": 129,
}

INVENTORY_RANDOM_VALUES = {
    "A": 621,
    "B": 721,
    "C": 821,
    "D": 921,
}

import os
import json
from math import gcd


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEY_DIR = os.path.join(BASE_DIR, "keys")


def mod_inverse(e, phi):
    return pow(e, -1, phi)


def build_rsa_key_file(name, p, q, e):
    n = p * q
    phi = (p - 1) * (q - 1)
    d = mod_inverse(e, phi)

    return {
        "name": name,
        "p": p,
        "q": q,
        "e": e,
        "n": n,
        "phi": phi,
        "d": d
    }


def save_key_files():
    os.makedirs(KEY_DIR, exist_ok=True)

    key_files = {
        "inventory_A_keys.json": build_rsa_key_file(
            "Inventory A",
            PART1_KEYS["A"]["p"],
            PART1_KEYS["A"]["q"],
            PART1_KEYS["A"]["e"]
        ),
        "inventory_B_keys.json": build_rsa_key_file(
            "Inventory B",
            PART1_KEYS["B"]["p"],
            PART1_KEYS["B"]["q"],
            PART1_KEYS["B"]["e"]
        ),
        "inventory_C_keys.json": build_rsa_key_file(
            "Inventory C",
            PART1_KEYS["C"]["p"],
            PART1_KEYS["C"]["q"],
            PART1_KEYS["C"]["e"]
        ),
        "inventory_D_keys.json": build_rsa_key_file(
            "Inventory D",
            PART1_KEYS["D"]["p"],
            PART1_KEYS["D"]["q"],
            PART1_KEYS["D"]["e"]
        ),
        "pkg_keys.json": build_rsa_key_file(
            "PKG",
            PART2_KEYS["PKG"]["p"],
            PART2_KEYS["PKG"]["q"],
            PART2_KEYS["PKG"]["e"]
        ),
        "user_keys.json": build_rsa_key_file(
            "Procurement Officer",
            PART2_KEYS["USER"]["p"],
            PART2_KEYS["USER"]["q"],
            PART2_KEYS["USER"]["e"]
        ),
    }

    for filename, data in key_files.items():
        path = os.path.join(KEY_DIR, filename)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)