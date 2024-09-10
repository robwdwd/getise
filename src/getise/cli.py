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
import shutil
import sys
import tempfile
import time
from io import TextIOWrapper
from json import JSONDecodeError
from re import Pattern

import click
import requests
from git import Repo
from netaddr import IPGlob, IPNetwork, cidr_merge
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from getise.exceptions import GetISEException

# Turn off warnings about invalid certificates
#
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

pp = pprint.PrettyPrinter(indent=4)


def join_errors(messages):
    return ":".join(message["title"] for message in messages)


def connect_ise(auth: tuple, headers: dict) -> requests.Session:
    """
    Establishes a connection to the ISE server using the provided authentication and headers.

    This function creates a new `requests.Session` object, sets the authentication credentials,
    and updates the session headers with the provided values. It returns the configured session
    ready for making requests to the ISE server.

    Args:
        auth (tuple): A tuple containing the authentication credentials.
        headers (dict): A dictionary of headers to be included in the session.

    Returns:
        requests.Session: A configured requests session for connecting to the ISE server.
    """
    s = requests.Session()
    s.auth = auth
    s.headers.update(headers)

    return s


def get_page(connection: requests.Session, url: str, page: int):
    try:
        resp = connection.get(url, verify=False, params={"page": page, "size": 100})
        resp.raise_for_status()
    except requests.exceptions.RequestException as err:
        raise GetISEException(f"Unable to get respose from the ISE server: {err}") from err

    if resp.status_code != 200:
        result = resp.json()
        error = join_errors(result["ERSResponse"]["messages"])
        raise GetISEException(f"GET-All-Devices: {resp.status_code} {error}")

    return resp.json()["SearchResult"]


def get_device(connection: requests.Session, url: str, device_id: str):
    device_url = f"{url}/{device_id}"

    try:
        resp = connection.get(device_url, verify=False)
        resp.raise_for_status()
    except requests.exceptions.RequestException as err:
        raise GetISEException(f"Unable to get respose from the ISE server: {err}") from err

    if resp.status_code != 200:
        result = resp.json()
        error = join_errors(result["ERSResponse"]["messages"])
        raise GetISEException(f"GET-Device: {resp.status_code} {error}")

    return resp.json()


def find_seedgroup_and_is_cpe(
    group_matches: dict[str, Pattern],
    cpe_group_matches: dict[str, Pattern],
    groups: list,
):
    for matches, is_cpe in [(cpe_group_matches, True), (group_matches, False)]:
        for group_name, pattern in matches.items():
            if any(pattern.match(g) for g in groups):
                return group_name, is_cpe
    return None, False

def do_device(
    device,
    cfg,
    device_re: dict[str, Pattern],
    group_matches: dict[str, Pattern],
    cpe_group_matches: dict[str, Pattern],
    gitseedfiles: dict,
    rejectfile: TextIOWrapper,
    dumpfile: TextIOWrapper,
):
    if "NetworkDevice" not in device:
        return

    device = device["NetworkDevice"]

    hostname = device["name"].lower()

    if device_re["skiphosts"].match(hostname):
        rejectfile.write(f"SKIPPED: [{hostname}] : Hostname matches skip host RE.\n")
        return

    groups = [item for group in device["NetworkDeviceGroupList"] if "Colt_NDGs" in group for item in group.split("#")]
    ipaddress = [ipaddr["ipaddress"] for ipaddr in device["NetworkDeviceIPList"]]

    if any(device_re["skipgroups"].match(g) for g in groups):
        rejectfile.write(f"SKIPPED: [{hostname}] : {groups} : Matches skip RE.\n")
        return

    seedgroup, is_cpe = find_seedgroup_and_is_cpe(group_matches, cpe_group_matches, groups)

    if not seedgroup:
        rejectfile.write(f"REJECTED: [{hostname}] : {groups} : Group match not found.\n")
        return
    
    if not is_cpe and not device_re["domaincheck"].match(hostname):
        hostname += "." + cfg["groupdomains"][seedgroup]

    dumpfile.write(f"hostname: {hostname}, ipaddresses: {ipaddress}, groups: {groups}, seedgroup: {seedgroup}\n")

    if is_cpe:
        for ip_range in ipaddress:
            if device_re["skipcpe"].match(ip_range):
                rejectfile.write(f"SKIPPED: [{ip_range}] : IP range Matches skip CPE RE.\n")
                continue
            dumpfile.write(f"hostname: {hostname}, Found iprange: {ip_range}\n")
            ip_range_cidrs = IPGlob(ip_range).cidrs()
            dumpfile.write(f"hostname: {hostname}, Converting iprange: {ip_range}, cidrs: {ip_range_cidrs}\n")

            for cidr in ip_range_cidrs:
                gitseedfiles[seedgroup]["handle"].write(f"{cidr}\n")
    else:
        gitseedfiles[seedgroup]["handle"].write(f"{hostname}\n")


def get_seedfiles(absolute_path: str, relative_path: str, group_seeds: dict, cpe_seeds: dict) -> dict:
    """
    Creates temporary seed files for both group and CPE seeds and returns a dictionary of their handles.

    This function initializes temporary files for each seed in the provided group and CPE dictionaries,
    storing relevant metadata such as file paths and whether the seed is a CPE list.

    Args:
        absolute_path (str): The absolute path where the temporary files will be created.
        relative_path (str): The relative path to be prepended to the seed file names.
        group_seeds (dict): A dictionary containing group names and their corresponding file names.
        cpe_seeds (dict): A dictionary containing CPE group names and their corresponding file names.

    Returns:
        dict: A dictionary mapping group names to their file information, including handles and paths.
    """
    gitseedfiles = {}

    for seeds, is_cpe in [(group_seeds, False), (cpe_seeds, True)]:
        for group_name, file_name in seeds.items():
            gitseedfiles[group_name] = {
                "is_cpe": is_cpe,
                "handle": tempfile.NamedTemporaryFile(
                    dir=absolute_path, prefix=f"{file_name}-", suffix=".tmp", mode="w+t"
                ),
                "file_relative": relative_path + file_name,
                "file_absolute": absolute_path + file_name,
            }

    return gitseedfiles


def sort_cpe_file(source_file: tempfile._TemporaryFileWrapper, destination_filename: str):
    """
    Sorts IP address ranges from the temporary source file, processes them to merge
    overlapping ranges, and writes the sorted results to the specified destination file.

    Args:
        source_file (tempfile._TemporaryFileWrapper): A temporary file object containing IP address ranges.
        destination_filename (str): The path to the destination file where sorted IP ranges will be written.

    Returns:
        None
    """
    source_file.seek(0)

    ip_ranges = [IPNetwork(line.strip()) for line in source_file]
    ip_sorted = cidr_merge(ip_ranges)

    with open(destination_filename, "w") as cpe_file:
        for cidr in ip_sorted:
            cpe_file.write(str(cidr) + "\n")


def process_seedfiles(gitseedfiles: dict):
    """
    Copies the temporary seedfiles to the final destination. If seedfiles
    is a list of CPE devices it sorts this list first.

    Args:
        gitseedfiles (dict): A dictionary containing file information, where each
                             value is expected to have a "handle" key pointing
                             to an open file object, an "is_cpe" key indicating
                             the device type contained in the file, and a "file_absolute"
                             key for the destination path.

    Raises:
        GetISEException: If a seed file is found with zero size.

    Returns:
        None
    """
    for file_info in gitseedfiles.values():
        file_info["handle"].flush()
        handle_name = file_info["handle"].name

        if os.path.getsize(handle_name) <= 0:
            raise GetISEException(f"Found raw seedfile with zero size: {handle_name}")

        if file_info["is_cpe"]:
            sort_cpe_file(file_info["handle"], file_info["file_absolute"])
        else:
            shutil.copy(handle_name, file_info["file_absolute"])


def close_seedfiles(gitseedfiles: dict):
    """
    Closes all file handles in the provided dictionary of seed files.

    Args:
        gitseedfiles (dict): A dictionary containing file information, where each
                             value is expected to have a "handle" key pointing
                             to an open file object.

    Returns:
        None
    """
    for file_info in gitseedfiles.values():
        file_info["handle"].close()


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

    try:
        cfg = json.load(cli_args["config"])
    except JSONDecodeError as err:
        raise SystemExit(f"Unable to parse configuration file: {err}") from err

    group_matches: dict[str, Pattern] = {}
    cpe_group_matches: dict[str, Pattern] = {}

    # Join and compile the regular expressions from the group matches
    #
    for gm in cfg["groupmatches"]:
        group_matches[gm] = re.compile("|".join(cfg["groupmatches"][gm]))

    # Group matches for CPE entries are seperate from the other groups.
    #
    for cm in cfg["cpematches"]:
        cpe_group_matches[cm] = re.compile("|".join(cfg["cpematches"][cm]))

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

    # Open the tacacs dump file
    #
    dumpfile = open(cfg["dumpfile"], "w")
    rejectfile = open(cfg["rejectfile"], "w")

    # Open the raw seedfiles for writing
    #
    gitseedfiles = get_seedfiles(
        cfg["git"]["absolute_path"], cfg["git"]["relative_path"], cfg["groupseeds"], cfg["cpeseeds"]
    )

    pp.pprint(gitseedfiles)

    try:
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
                    group_matches,
                    cpe_group_matches,
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
                group_matches,
                cpe_group_matches,
                gitseedfiles,
                rejectfile,
                dumpfile,
            )

        process_seedfiles(gitseedfiles)

    except GetISEException as error:
        time.sleep(30)
        raise SystemExit(f"Aborting due to error: {error}")
    finally:
        close_seedfiles(gitseedfiles)
        ise_session.close()

    sys.exit()

    # Create Git repository object.
    #
    git_repo = Repo(cfg["git"]["basedir"])

    # Pull in updates from the repository to make sure we are
    # up-to-date with everything.
    #
    origin = git_repo.remotes["origin"]
    secondary = git_repo.remotes["secondary"]
    origin.pull()

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

    # Clean up the logging.
    #
    rejectfile.flush()
    dumpfile.flush()
    rejectfile.close()
    dumpfile.close()
