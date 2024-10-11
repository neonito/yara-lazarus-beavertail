rule lazarus_beaver_tail_detection {

    meta:
        description = "apt beaver tail detection"
        author = "neonito"

    strings:
        $ssh_obj = "ssh_obj"
        $ssh_upload = "ssh_upload"
        $ssh_any = "ssh_any"
        $ssh_env = "ssh_env"
        $ssh_zcp = "ssh_zcp"
        $rport = "PORT = 1244"
        $send_tg = "def send_tg"
        $telegram_api = "https://api.telegram.org/bot"
        $send_document = "files = {'document': fp};data = {'chat_id': cid}"
        $browser_init = "def __init__(A, prof_dirs=_N)"
        $linux_profiles_1 = "chromium/s_df"
        $linux_profiles_2 = "chromium/s_pf"
        $windows_profiles_1 = "Chromium\\\\User Data\\\\s_df"
        $windows_profiles_2 = "Chromium\\\\User Data\\\\s_pf"
        $osx_profiles_1 = "Chromium/s_df"
        $osx_profiles_2 = "Chromium/s_pf"

    condition:
        (3 of (
            $ssh_obj, 
            $ssh_upload, 
            $ssh_any, 
            $ssh_env, 
            $ssh_zcp, 
            $send_tg, 
            $telegram_api,
            $rport,
            $send_document
        )) and $rport

        or any of (
            $browser_init, 
            $linux_profiles_1, 
            $linux_profiles_2, 
            $windows_profiles_1, 
            $windows_profiles_2, 
            $osx_profiles_1, 
            $osx_profiles_2
        )

}