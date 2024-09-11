#!/usr/bin/env python3
# Copyright (c), Rob Woodward. All rights reserved.
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


def join_errors(messages: list) -> str:
    """Join error messages into a single string.

    Args:
        messages (list): A list of dictionaries, each containing an error message
            with a "title" key.

    Returns:
        str: Joined error string.
    """
    return ":".join(message["title"] for message in messages)


def create_session(auth: tuple, headers: dict) -> requests.Session:
    """
    Creates a session to use with ISE server API.

    Args:
        auth (tuple): The authentication credentials.
        headers (dict): Headers to be included in the session.

    Returns:
        requests.Session: A configured requests session for connecting to the ISE server.
    """
    s = requests.Session()
    s.auth = auth
    s.headers.update(headers)

    return s


def get_ise_data(
    ise_session: requests.Session,
    url: str,
    group_domains: dict[str, str],
    device_regex: dict[str, Pattern],
    group_matches: dict[str, Pattern],
    cpe_group_matches: dict[str, Pattern],
    gitseedfiles: dict,
    rejectfile: TextIOWrapper,
    dumpfile: TextIOWrapper,
):
    """Retrieve and process device data from the ISE API.

    Args:
        ise_session (requests.Session): The session object used to make API requests.
        url (str): The base URL for the ISE API.
        group_domains (dict[str, str]): A mapping of group domains.
        device_regex (dict[str, Pattern]): Regular expressions for device matching.
        group_matches (dict[str, Pattern]): Patterns for group matching.
        cpe_group_matches (dict[str, Pattern]): Patterns for CPE group matching.
        gitseedfiles (dict): A dictionary of Git seed files.
        rejectfile (TextIOWrapper): A file-like object for logging rejected devices.
        dumpfile (TextIOWrapper): A file-like object for dumping processed device data.

    """
    page = 1
    result = get_page(ise_session, url, page)

    while "nextPage" in result:
        for device in result["resources"]:
            do_device(
                get_device(ise_session, url, device["id"]),
                group_domains,
                device_regex,
                group_matches,
                cpe_group_matches,
                gitseedfiles,
                rejectfile,
                dumpfile,
            )
        page += 1
        result = get_page(ise_session, url, page)

    for device in result["resources"]:
        do_device(
            get_device(ise_session, url, device["id"]),
            group_domains,
            device_regex,
            group_matches,
            cpe_group_matches,
            gitseedfiles,
            rejectfile,
            dumpfile,
        )


def get_page(ise_session: requests.Session, url: str, page: int):
    """Retrieve a page of results from the ISE server.

    Args:
        ise_session (requests.Session): The session object used to make the request.
        url (str): The base URL of the ISE server.
        page (int): The page number to retrieve.

    Returns:
        dict: The JSON response containing the results for the specified page.

    Raises:
        GetISEException: If there is an error in the request or if the response indicates a failure.
    """
    try:
        resp = ise_session.get(url, verify=False, params={"page": page, "size": 100})
        resp.raise_for_status()
    except requests.exceptions.RequestException as err:
        raise GetISEException(f"Unable to get respose from the ISE server: {err}") from err

    if resp.status_code != 200:
        result = resp.json()
        error = join_errors(result["ERSResponse"]["messages"])
        raise GetISEException(f"GET-All-Devices: {resp.status_code} {error}")

    return resp.json()["SearchResult"]


def get_device(ise_session: requests.Session, url: str, device_id: str):
    """Retrieve single device information from the ISE server.

    Args:
        connection (requests.Session): The session object used to make the request.
        url (str): The base URL of the ISE server.
        device_id (str): The unique identifier of the device to retrieve.

    Returns:
        dict: The JSON response containing device information.

    Raises:
        GetISEException: If there is an error in the request or if the response indicates a failure.
    """
    device_url = f"{url}/{device_id}"

    try:
        resp = ise_session.get(device_url, verify=False)
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
    """Determine the matching seed group name and if it is a CPE.

    Args:
        group_matches (dict[str, Pattern]): A dictionary of group names and their corresponding regex patterns.
        cpe_group_matches (dict[str, Pattern]): A dictionary of CPE group names and their corresponding regex patterns.
        groups (list): A list of group names to be checked against the patterns.

    Returns:
        tuple: A tuple containing the name of the matching group and a boolean indicating if it is a CPE group.
               Returns (None, False) if no match is found.
    """
    for matches, is_cpe in [(cpe_group_matches, True), (group_matches, False)]:
        for group_name, pattern in matches.items():
            if any(pattern.match(g) for g in groups):
                return group_name, is_cpe
    return None, False


def do_device(
    device,
    group_domains: dict[str, str],
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

    groups = []
    for group in device["NetworkDeviceGroupList"]:
        if "Colt_NDGs" in group:
            groups.extend(group.split("#"))

    ipaddress = [ipaddr["ipaddress"] for ipaddr in device["NetworkDeviceIPList"]]

    if any(device_re["skipgroups"].match(g) for g in groups):
        rejectfile.write(f"SKIPPED: [{hostname}] : {groups} : Matches skip RE.\n")
        return

    seedgroup, is_cpe = find_seedgroup_and_is_cpe(group_matches, cpe_group_matches, groups)

    if not seedgroup:
        rejectfile.write(f"REJECTED: [{hostname}] : {groups} : Group match not found.\n")
        return

    if not is_cpe and not device_re["domaincheck"].match(hostname):
        hostname += f".{group_domains[seedgroup]}"

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
    Creates temporary seed files and the paths to final seedfiles.

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


def compile_patterns(pattern_dict: dict[str, str]) -> dict[str, Pattern]:
    """Compile a dictionary of string patterns into regex patterns.

    Args:
        pattern_dict (dict[str, str]): A dictionary of keys and their associated string patterns.

    Returns:
        dict[str, Pattern]: A dictionary mapping each key to its compiled regex pattern.
    """
    return {key: re.compile("|".join(patterns)) for key, patterns in pattern_dict.items()}


def update_git(base_dir: str, gitseedfiles: dict):
    """Update the Git repository with new files from the specified directory.

    Args:
        base_dir (str): The base directory of the Git repository.
        gitseedfiles (dict): A dictionary containing file information.

    """
    git_repo = Repo(base_dir)
    origin = git_repo.remotes["origin"]
    secondary = git_repo.remotes["secondary"]
    origin.pull()

    file_paths = [details["file_relative"] for details in gitseedfiles.values()]
    git_repo.index.add(file_paths)

    if git_repo.is_dirty():
        git_repo.index.commit("Get ISE Devices automated commit")
        origin.push()
        secondary.push()


def load_config(config_file):
    try:
        return json.load(config_file)
    except JSONDecodeError as err:
        raise SystemExit(f"Unable to parse configuration file: {err}") from err


@click.command()
@click.option(
    "--config",
    metavar="CONFIG_FILE",
    help="Configuaration file to load.",
    default=os.path.join(os.environ["HOME"], ".config", "getise", "config.json"),
    envvar="GETISE_CONFIG_FILE",
    type=click.File(mode="r"),
)
def cli(**cli_args):

    cfg = load_config(cli_args["config"])

    group_matches: dict[str, Pattern] = compile_patterns(cfg["groupmatches"])
    cpe_group_matches: dict[str, Pattern] = compile_patterns(cfg["cpematches"])

    device_regex: dict[str, Pattern] = {
        "skipgroups": re.compile("|".join(cfg["skipgroups"])),  # Groups to skip
        "skiphosts": re.compile("|".join(cfg["skiphosts"])),  # Hostnames to skip
        "skipcpe": re.compile("|".join(cfg["skipcpe"])),  # CPE IP Ranges to skip
        "domaincheck": re.compile(
            "|".join(cfg["domaincheck"])
        ),  # Any hostname matching this doesn't need domain adding
    }

    # Open the raw seedfiles for writing
    #
    gitseedfiles = get_seedfiles(
        cfg["git"]["absolute_path"], cfg["git"]["relative_path"], cfg["groupseeds"], cfg["cpeseeds"]
    )

    with open(cfg["dumpfile"], "w") as dumpfile, open(cfg["rejectfile"], "w") as rejectfile:
        try:
            ise_session = create_session(
                (cfg["ise"]["user"], cfg["ise"]["password"]),
                {"Content-Type": "application/json", "Accept": "application/json"},
            )

            get_ise_data(
                ise_session,
                cfg["ise"]["url"],
                cfg["groupdomains"],
                device_regex,
                group_matches,
                cpe_group_matches,
                gitseedfiles,
                rejectfile,
                dumpfile,
            )

            process_seedfiles(gitseedfiles)

        except GetISEException as error:
            raise SystemExit(f"Aborting due to error: {error}") from error
        finally:
            close_seedfiles(gitseedfiles)
            ise_session.close()

    update_git(cfg["git"]["basedir"], gitseedfiles)
