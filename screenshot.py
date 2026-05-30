from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import time

def capture_screenshot(url, save_path="screenshot.png"):
    try:
        options = Options()
        options.headless = True
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--window-size=1280,800')
        driver = webdriver.Chrome(options=options)
        driver.set_page_load_timeout(10)
        driver.get(url)
        time.sleep(2)
        driver.save_screenshot(save_path)
        driver.quit()
        return save_path
    except Exception as e:
        print(f"Screenshot error: {e}")
        return None
