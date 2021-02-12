# keepass_audit

Command line utiltity for auditing keepass databases and automatically expiring weak passwords.

It uses [pykeepass](https://github.com/libkeepass/pykeepass) for interacting with your keepass database,
so make sure you trust that library as well as this project. :)

## Installation

```sh
git clone git@github.com:theCalcaholic/keepass_audit.git
cd keepass_audit
virtualenv -p python3 .venv
. ./.venv/bin/activate
python ./kp-audit.py --help
```

## Usage

```sh
$ ./kp-audit.py --help
usage: kp-audit.py [-h] [--blacklist [PASSWORD [PASSWORD ...]]] [--min-score MIN_SCORE] [--expire EXPIRE] [--show-passwords] passwords_file

positional arguments:
  passwords_file        Your keepass database (probably a .kdbx file).

optional arguments:
  -h, --help            show this help message and exit
  --blacklist [PASSWORD [PASSWORD ...]], -b [PASSWORD [PASSWORD ...]]
                        A list of frequently used passwords that should receive a harsh penalty in their scores
  --min-score MIN_SCORE, -s MIN_SCORE
                        All passwords with a score less than this value will be printed
  --expire EXPIRE, -e EXPIRE
                        If set, all passwords scored below --min-score will be expired at the given date or interval. 
                        Format: YYYY-MM-DD | Day Month Year (cron-like syntax, example: '*/7 * 2025' will expire on password every 7 days
                        in 2025)
  --show-passwords
```
