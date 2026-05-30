from detector import PhishingDetector

def main():
    url = input("Enter a website URL to check for phishing: ")
    detector = PhishingDetector(url)
    result = detector.detect_phishing()
    print("Phishing Detection Result:", result)

if __name__ == "__main__":
    main()
