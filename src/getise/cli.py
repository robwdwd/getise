#!/usr/bin/env python3
# Copyright (c) 2023, Rob Woodward. All rights reserved.
#
# This file is part of Get ISE tool and is released under the
# "BSD 2-Clause License". Please see the LICENSE file that should
# have been included as part of this distribution.
#


import json
import os
import pprint
import re
from io import TextIOWrapper
from json import JSONDecodeError
from re import Pattern

import click
import requests
from git import Repo
from netaddr import IPGlob, IPNetwork, cidr_merge
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Turn off warnings about invalid certificates
#
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

pp = pprint.PrettyPrinter(indent=4)


def join_errors(messages):
    m = ""
    for message in messages:
        m = m + ":" + message["title"]

    return m


def connect_ise(auth: tuple, headers: dict) -> requests.Session:
    s = requests.Session()
    s.auth = auth
    s.headers.update(headers)

    return s


# Get 1 page of devices from the ISE
#


def get_page(connection: requests.Session, url: str, page: int):
    resp = connection.get(url, verify=False, params={"page": page, "size": 100})

    if resp.status_code != 200:
        result = resp.json()
        error = join_errors(result["ERSResponse"]["messages"])
        raise Exception("GET-All-Devices: {} {}".format(resp.status_code, error))

    return resp.json()["SearchResult"]


# Get a single device from the ISE
#
def get_device(connection: requests.Session, url: str, id: str):
    device_url = url + "/" + id

    resp = connection.get(device_url, verify=False)

    if resp.status_code != 200:
        result = resp.json()
        error = join_errors(result["ERSResponse"]["messages"])
        raise Exception("GET-Device: {} {}".format(resp.status_code, error))

    return resp.json()


# Work out which seedfile the device belongs too or reject it.
#


def do_device(
    device,
    cfg,
    device_re: dict[str, Pattern],
    matchgroups: dict,
    matchcpe: dict,
    gitseedfiles: dict,
    rejectfile: TextIOWrapper,
    dumpfile: TextIOWrapper,
):
    if "NetworkDevice" in device:
        device = device["NetworkDevice"]
    else:
        return

    hostname = device["name"].lower()
    groups = []
    ipaddress = []
    seedgroup = None
    is_cpe = False

    if device_re["skiphosts"].match(hostname):
        rejectfile.write("SKIPPED: [" + hostname + "] : Hostname matches skip host RE.\n")
        return

    for group in device["NetworkDeviceGroupList"]:
        if group.find("Colt_NDGs") != -1:
            groups.extend(group.split("#"))

    if any(device_re["skipgroups"].match(g) for g in groups):
        rejectfile.write("SKIPPED: [" + hostname + "] : " + str(groups) + " : Matches skip RE.\n")
        return

    for cm_re in matchcpe:
        if any(matchcpe[cm_re].match(g) for g in groups):
            seedgroup = cm_re
            is_cpe = True
            break

    if not is_cpe:
        for gm_re in matchgroups:
            if any(matchgroups[gm_re].match(g) for g in groups):
                if not device_re["domaincheck"].match(hostname):
                    hostname = hostname + "." + cfg["groupdomains"][gm_re]
                seedgroup = gm_re
                break

    if not seedgroup:
        rejectfile.write("REJECTED: [" + hostname + "] : " + str(groups) + " : Group match not found.\n")
        return

    for ipaddr in device["NetworkDeviceIPList"]:
        ipaddress.append(ipaddr["ipaddress"])

    dumpfile.write(
        "hostname: "
        + hostname
        + ", ipaddresses: "
        + str(ipaddress)
        + ", groups: "
        + str(groups)
        + ", seedgroup: "
        + seedgroup
        + "\n"
    )

    if is_cpe:
        for ip_range in ipaddress:
            if device_re["skipcpe"].match(ip_range):
                rejectfile.write("SKIPPED: [" + ip_range + "] : IP range Matches skip CPE RE.\n")
                continue
            dumpfile.write("hostname: " + hostname + ", Found iprange: " + str(ip_range) + "\n")
            ip_range_cidrs = IPGlob(ip_range).cidrs()
            dumpfile.write(
                "hostname: "
                + hostname
                + ", Converting iprange: "
                + str(ip_range)
                + ", cidrs: "
                + str(ip_range_cidrs)
                + "\n"
            )

            for cidr in ip_range_cidrs:
                gitseedfiles[seedgroup]["handle"].write(str(cidr) + "\n")
    else:
        gitseedfiles[seedgroup]["handle"].write(hostname + "\n")


@click.command()
@click.option(
    "--config",
    metavar="CONFIG_FILE",
    help="Configuaration file to load.",
    default=os.environ["HOME"] + "/.config/getise/config.json",
    envvar="GETISE_CONFIG_FILE",
    type=click.File(mode="r"),
)
def cli(**cli_args):
    matchgroups = {}
    matchcpe = {}

    try:
        cfg = json.load(cli_args["config"])
    except JSONDecodeError as err:
        raise SystemExit(f"Unable to parse configuration file: {err}") from err

    # Join and compile the regular expressions from the group matches
    #
    for gm in cfg["groupmatches"]:
        matchgroups[gm] = re.compile("|".join(cfg["groupmatches"][gm]))

    # Group matches for CPE entries are seperate from the other groups.
    #
    for cm in cfg["cpematches"]:
        matchcpe[cm] = re.compile("|".join(cfg["cpematches"][cm]))

    device_regex: dict[str, Pattern] = {}
    # Device groups to ignore.
    #
    device_regex["skipgroups"] = re.compile("|".join(cfg["skipgroups"]))

    # Hostnames to ignore.
    #
    device_regex["skiphosts"] = re.compile("|".join(cfg["skiphosts"]))

    # Skip IP ranges in CPE devices.
    #
    device_regex["skipcpe"] = re.compile("|".join(cfg["skipcpe"]))

    # Any host that does have a domain ending to the hostname doesn't need another one
    # Matching domains are here so we know if there is one or not.
    #
    device_regex["domaincheck"] = re.compile("|".join(cfg["domaincheck"]))

    # Open the raw seedfiles for writing
    #
    gitseedfiles = {}

    for gs in cfg["groupseeds"]:
        gitseedfiles[gs] = {}
        gitseedfiles[gs]["handle"] = open(cfg["git"]["absolute_path"] + cfg["groupseeds"][gs], "w")
        gitseedfiles[gs]["file_relative"] = cfg["git"]["relative_path"] + cfg["groupseeds"][gs]
        gitseedfiles[gs]["file_absolute"] = cfg["git"]["absolute_path"] + cfg["groupseeds"][gs]

    for cs in cfg["cpeseeds"]:
        gitseedfiles[cs] = {}
        gitseedfiles[cs]["handle"] = open(cfg["git"]["absolute_path"] + cfg["cpeseeds"][cs], "w")
        gitseedfiles[cs]["file_relative"] = cfg["git"]["relative_path"] + cfg["cpeseeds"][cs]
        gitseedfiles[cs]["file_absolute"] = cfg["git"]["absolute_path"] + cfg["cpeseeds"][cs]

    # Open the tacacs dump file
    #
    dumpfile = open(cfg["dumpfile"], "w")
    rejectfile = open(cfg["rejectfile"], "w")

    url = cfg["ise"]["url"]

    # Open session to the ISE server.
    #
    ise_session = connect_ise(
        (cfg["ise"]["user"], cfg["ise"]["password"]),
        {"Content-Type": "application/json", "Accept": "application/json"},
    )

    # Get the first page of results.
    #
    page = 1
    result = get_page(ise_session, url, page)

    # If there is a nextPage then continue round the loop
    #
    while "nextPage" in result:
        for device in result["resources"]:
            do_device(
                get_device(ise_session, url, device["id"]),
                cfg,
                device_regex,
                matchgroups,
                matchcpe,
                gitseedfiles,
                rejectfile,
                dumpfile,
            )

        page = page + 1
        result = get_page(ise_session, url, page)

    # Finally catch the last page of results.
    for device in result["resources"]:
        do_device(
            get_device(ise_session, url, device["id"]),
            cfg,
            device_regex,
            matchgroups,
            matchcpe,
            gitseedfiles,
            rejectfile,
            dumpfile,
        )

    # Create Git repository object.
    #
    git_repo = Repo(cfg["git"]["basedir"])

    # Pull in updates from the repository to make sure we are
    # up-to-date with everything.
    #
    origin = git_repo.remotes["origin"]
    secondary = git_repo.remotes["secondary"]
    origin.pull()

    # Close and flush all the files
    #
    for open_file in gitseedfiles:
        gitseedfiles[open_file]["handle"].flush()
        gitseedfiles[open_file]["handle"].close()

    # Sort the CPE files
    #
    for cs in cfg["cpeseeds"]:
        cpe_file = open(cfg["git"]["absolute_path"] + cfg["cpeseeds"][cs], "r")
        ip_ranges = []
        for line in cpe_file:
            line = line.strip()
            ip_ranges.append(IPNetwork(line))

        cpe_file.close()

        ip_sorted = cidr_merge(ip_ranges)

        cpe_file = open(cfg["git"]["absolute_path"] + cfg["cpeseeds"][cs], "w")
        for cidr in ip_sorted:
            cpe_file.write(str(cidr) + "\n")

        cpe_file.flush()
        cpe_file.close()

    # Stage the file in git.
    #
    for git_file in gitseedfiles:
        git_repo.index.add([gitseedfiles[git_file]["file_relative"]])

    # If we have changed files then stage and push them.
    #
    if git_repo.is_dirty():
        git_repo.index.commit("Get ISE Devices automated commit")
        origin.push()
        secondary.push()

    ise_session.close()

    # Clean up the logging.
    #
    rejectfile.flush()
    dumpfile.flush()
    rejectfile.close()
    dumpfile.close()
