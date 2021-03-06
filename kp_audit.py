#!/usr/bin/env python

import io
import csv
import subprocess
import argparse
from pykeepass import PyKeePass
from pykeepass.entry import Entry
from datetime import date, timedelta, datetime, time
from getpass import getpass
from zxcvbn import zxcvbn
from zxcvbn.matching import add_frequency_lists
from typing import List, Any, Tuple, Dict


def perform_audit(keepass: PyKeePass, pws: List[str], score: float, show_passwords=False) -> List[Tuple[float, Entry]]:
    global pw_column

    add_frequency_lists({
        "my_passwords": [pw.lower() for pw in pws]
    })

    pw_data = [entry for entry in keepass.entries if isinstance(entry, Entry) and entry.password is not None]

    annotated = map(lambda entry: (get_zxcvbn_score(entry), entry), pw_data)
    filtered = filter(lambda entry: entry[0] < score, annotated)
    sorted_entries = sorted(filtered, key=lambda entry: entry[0])

    print_pws(sorted_entries, show_passwords)

    return sorted_entries


def print_pws(pws: List[Tuple[float, Entry]], show_passwords=False):
    for entry in pws:
        pw_string = entry[1].password if show_passwords else '*' * len(entry[1].password)
        print(f"{entry[0]:.4f}::{pw_string}:  {entry[1].group}/{entry[1].title}")


def get_zxcvbn_score(entry: Entry):
    evaluation = zxcvbn(entry.password)
    return evaluation['guesses_log10']


def import_password_data(database_path: str) -> List[Dict[str, Any]]:

    pw_data = []
    if database_path.endswith(".csv"):
        csv_stream = open(database_path, 'r')
    elif database_path.endswith(".kdbx"):

        db_password = getpass(f"Please enter the password for {database_path}: ")
        proc = subprocess.Popen(f"keepassxc.cli export -f csv {database_path}", stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, shell=True, text=True)
        csv_data = proc.communicate(input=db_password)[0]
        csv_stream = io.StringIO(csv_data)
    else:
        raise IOError(f"Invalid file type: {database_path}")

    csv_reader = csv.reader(csv_stream, delimiter=',', quotechar='"')
    keys = next(csv_reader)
    for row in csv_reader:
        entry = {}
        for key, field in zip(keys, row):
            entry[key] = field
        pw_data.append(entry)

    csv_stream.close()

    return pw_data


def get_expiration_dates(cron_spec: Tuple[float], start_date: date = None):
    if start_date is not None:
        yield start_date
        current = start_date
    else:
        current = date.today()

    while True:
        if 1 <= cron_spec[2] != current.year:
            current = current.replace(day=1, month=1, year=int(cron_spec[2]))

        month_offset = current.month
        # iterate over months in year
        while cron_spec[2] == 0 or (cron_spec[2] < 1 and current.year % (1 / cron_spec[2]) == 0) \
                or current.year == cron_spec[2]:

            if cron_spec[1] >= 1:
                current = current.replace(month=int(cron_spec[1]))

            # iterate over days in month
            current_month = current.month

            while cron_spec[1] == 0 or (cron_spec[1] < 1 and (current.month - month_offset) % (1 / cron_spec[1]) == 0) \
                    or current.month == cron_spec[1]:
                if cron_spec[0] < 1:
                    if current >= date.today():
                        yield current
                    increment = 1 if cron_spec[0] == 0 else int(1 / cron_spec[0])
                    current += timedelta(days=increment)
                else:
                    current = current.replace(day=int(cron_spec[0]))
                    if current >= date.today():
                        yield current
                    break

            # reset day
            current = current.replace(day=1)

            # set/increment month
            if cron_spec[1] < 1:
                increment = 1 if cron_spec[1] == 0 else int(1 / cron_spec[1])

                # if no months left
                if current.month + increment > 12:
                    # increment year and month remainder
                    current = current.replace(year=current.year + 1, month=increment - 12 + current_month)
                    month_offset = current.month
                    continue
                current = current.replace(month=current_month + increment)
            else:
                current = current.replace(month=int(cron_spec[1]))
                break

        current = current.replace(month=1, day=1)
        if cron_spec[2] < 1:
            increment = 1 if cron_spec[2] == 0 else (1 / cron_spec[2])
            current = current.replace(year=current.year + increment)
            month_offset = current.month
        else:
            return


def expire_weak_passwords(keepass: PyKeePass, audit_data: List[Tuple[float, Entry]], exp_date: date,
                          exp_cron: Tuple[float]):

    if exp_date is None:
        expiration_dates = get_expiration_dates(exp_cron)
    else:
        expiration_dates = [exp_date] * len(audit_data)

    for entry, expire in zip(audit_data, expiration_dates):
        entry[1].expiry_time = datetime.combine(expire, time())
        entry[1].expires = True
        print(f"'{'/'.join(entry[1].path)}' will expire on {entry[1].expiry_time}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("passwords_file", type=str, help="Your keepass database (probably a .kdbx file).")
    parser.add_argument("--blacklist", "-b", type=str, nargs="*", default=[], metavar="PASSWORD",
                        help="A list of frequently used passwords that should receive a harsh penalty in their scores")
    parser.add_argument("--min-score", "-s", default=16, help="All passwords with a score less than this value will be "
                                                              "printed")
    parser.add_argument("--expire", "-e", type=str, help="If set, all passwords scored below --min-score will be "
                                                         "expired at the given date or interval.\n"
                                                         "Format: YYYY-MM-DD | Day Month Year (cron-like syntax, "
                                                         "example: '*/7 * 2025' will expire on password every "
                                                         "7 days in 2025)")
    parser.add_argument('--show-passwords', action='store_true')

    args = parser.parse_args()

    # pws = [] if len(sys.argv) == 2 else sys.argv[2:]
    expiration_date = expiration_cron = None
    if args.expire:
        try:
            expiration_date = date.fromisoformat(args.expire)
        except ValueError as e:
            expiration_split = args.expire.split(" ")

            expiration_cron = []
            for val in expiration_split:
                if val == "*":
                    expiration_cron.append(0)
                elif val.startswith("*"):
                    expiration_cron.append(1/float(val[2:]))
                else:
                    expiration_cron.append(float(val))

            if len(expiration_cron) != 3 or len([x for x in expiration_cron if x >= 1 and float(x) != int(x)]) > 0:
                raise ValueError(f"Invalid format for --expire: {args.expire}")

    min_score = None if args.min_score is None else float(args.min_score)

    kp = PyKeePass(args.passwords_file, getpass(f'Please enter the password for {args.passwords_file}: '))

    audit_result = perform_audit(kp, args.blacklist, min_score, args.show_passwords)

    print("\n########## EXPIRE WEAK PASSWORDS ##########\n")

    expire_weak_passwords(kp, audit_result, expiration_date, tuple(expiration_cron))

    print("")
    choice = ''
    while choice.lower() not in ['y', 'n']:
        choice = input("Apply changes? (y/N)")
    if choice.lower() == 'y':
        print(f"Saving to {args.passwords_file}")
        kp.save()
    else:
        print("Not saving. Changes will be lost.")
