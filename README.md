# YARA Rule: lazarus_beaver_tail_detection

## Description
The YARA rule `lazarus_beaver_tail_detection` is designed to detect malicious software written in Python, known as **BeaverTail**, which is associated with the Lazarus hacking group.

## Author
- neonito

## Strings Section
The rule contains the following strings used to detect BeaverTail malware:

- `$ssh_obj = "ssh_obj"`
- `$ssh_upload = "ssh_upload"`
- `$ssh_any = "ssh_any"`
- `$ssh_env = "ssh_env"`
- `$ssh_zcp = "ssh_zcp"`
- `$rport = "PORT = 1244"`
- `$send_tg = "def send_tg"`
- `$telegram_api = "https://api.telegram.org/bot"`
- `$send_document = "files = {'document': fp};data = {'chat_id': cid}"`
- `$browser_init = "def __init__(A, prof_dirs=_N)"`
- `$linux_profiles_1 = "chromium/s_df"`
- `$linux_profiles_2 = "chromium/s_pf"`
- `$windows_profiles_1 = "Chromium\\\\User Data\\\\s_df"`
- `$windows_profiles_2 = "Chromium\\\\User Data\\\\s_pf"`
- `$osx_profiles_1 = "Chromium/s_df"`
- `$osx_profiles_2 = "Chromium/s_pf"`

## Condition Section
Conditions that must be met for the rule to trigger:

1. At least 3 of the following conditions must be satisfied:
    - `$ssh_obj`
    - `$ssh_upload`
    - `$ssh_any`
    - `$ssh_env`
    - `$ssh_zcp`
    - `$send_tg`
    - `$telegram_api`
    - `$rport`
    - `$send_document`

2. Or any of the following conditions:
    - `$browser_init`
    - `$linux_profiles_1`
    - `$linux_profiles_2`
    - `$windows_profiles_1`
    - `$windows_profiles_2`
    - `$osx_profiles_1`
    - `$osx_profiles_2`

## Usage
To use this YARA rule, add it to your rule set and run a scan on suspicious files or processes.
