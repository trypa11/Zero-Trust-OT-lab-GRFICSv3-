import sys
import time
import os
from datetime import datetime, timedelta
from playwright.sync_api import sync_playwright

def log_time(step_name):
    # Use UTC+3 for consistency with host logs (Athens time)
    now = datetime.now() + timedelta(hours=3)
    now_str = now.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    print(f"[*] Step: {step_name}")
    print(f"  [TIME] {now_str}")

def main():
    stop_file = "/tmp/guac_stop.txt"
    try:
        if os.path.exists(stop_file):
            os.remove(stop_file)
    except Exception: pass

    with sync_playwright() as p:
        log_time("Launching Chromium browser for Guacamole Attack")
        browser = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-setuid-sandbox"])
        
        context = browser.new_context(ignore_https_errors=True)
        context.set_default_timeout(60000)
        page = context.new_page()

        log_time("Navigating to Zero-Trust Gateway (Guacamole)")
        page.goto("https://guacamole.localhost.pomerium.io/")
        
        for i in range(15): 
            time.sleep(2)
            
            if page.locator("#kc-login").count() > 0:
                log_time("Authenticating Pomerium via Keycloak")
                page.fill("input[name='username']", "admin")
                page.fill("input[name='password']", "admin")
                page.click("#kc-login")
                time.sleep(3)
                continue
                
            if page.locator("text='Sign in'").count() > 0 and "pomerium" in page.url:
                try: page.click("text='Sign in'", timeout=5000)
                except: pass
                continue
                
            if page.locator(".login-ui").count() > 0:
                log_time("Authenticating to Guacamole Console")
                page.fill("input[type='text']", "guacadmin")
                page.fill("input[type='password']", "guacadmin")
                page.keyboard.press("Enter")
                time.sleep(3)
                continue
                
            if page.locator("text='EWS'").count() > 0:
                break

        time.sleep(2)
        log_time("Opening remote desktop session (VNC) to EWS")
        
        # Click the EWS connection box in the UI
        try:
            page.wait_for_selector("text='EWS'", timeout=10000)
            page.click("text='EWS'")
            # Wait for canvas to load
            time.sleep(5)
            log_time("VNC Session Active. Waiting for attacker actions...")
            
            # Touch a purely communicative ready file
            with open("/tmp/guac_ready.txt", "w") as f:
                f.write("ready")
                
        except Exception as e:
            print(f"[-] Could not find or click EWS connection in Guacamole: {e}")
            browser.close()
            sys.exit(1)

        # Keep session alive until signaled to stop or timeout after 60s
        for _ in range(60):
            if os.path.exists(stop_file):
                log_time("Received stop signal. Closing VNC Session")
                break
            time.sleep(1)

        try: os.remove("/tmp/guac_ready.txt")
        except: pass
        
        browser.close()

if __name__ == "__main__":
    main()
