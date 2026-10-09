import json
from datetime import datetime
import requests
from bs4 import BeautifulSoup


class ThreatIntelScraper:
    """A modular scraper designed to collect raw cybersecurity threat news

    from multiple industry publications.
    """

    def __init__(self):
        # Realistic User-Agent header prevents target servers from blocking our requests (HTTP 403)
        self.headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/115.0.0.0 Safari/537.36"
            )
        }
        self.collected_threats = []

    def fetch_hacker_news(self, limit: int = 3):
        """Scrapes the latest vulnerability articles from The Hacker News."""
        url = "https://thehackernews.com/"
        try:
            response = requests.get(url, headers=self.headers, timeout=10)
            if response.status_code != 200:
                print(
                    f"[-] Failed to load The Hacker News: Status {response.status_code}"
                )
                return

            soup = BeautifulSoup(response.text, "html.parser")
            # Locate article story containers
            stories = soup.find_all("div", class_="body-post", limit=limit)

            for story in stories:
                title_tag = story.find("h2", class_="home-title")
                snippet_tag = story.find("div", class_="home-desc")
                link_tag = story.find("a", class_="story-link")

                if title_tag and snippet_tag and link_tag:
                    threat_entry = {
                        "source": "The Hacker News",
                        "title": title_tag.get_text(strip=True),
                        "summary": snippet_tag.get_text(strip=True),
                        "url": link_tag.get("href"),
                        "scraped_at": datetime.now().isoformat(),
                    }
                    self.collected_threats.append(threat_entry)
            print(f"[+] Successfully scraped {len(stories)} articles from THN.")
        except Exception as e:
            print(f"[-] Error scraping The Hacker News: {str(e)}")

    def fetch_bleeping_computer(self, limit: int = 3):
        """Scrapes security alerts from BleepingComputer's security news page."""
        url = "https://www.bleepingcomputer.com/news/security/"
        try:
            response = requests.get(url, headers=self.headers, timeout=10)
            if response.status_code != 200:
                print(
                    f"[-] Failed to load BleepingComputer: Status {response.status_code}"
                )
                return

            soup = BeautifulSoup(response.text, "html.parser")
            # BleepingComputer groups articles in the bc_latest_news section
            news_items = soup.find_all("li", class_="bc_news_item", limit=limit)

            for item in news_items:
                headline = item.find("h4")
                snippet = item.find("p")
                link = item.find("a")

                if headline and snippet and link:
                    threat_entry = {
                        "source": "BleepingComputer",
                        "title": headline.get_text(strip=True),
                        "summary": snippet.get_text(strip=True),
                        "url": link.get("href"),
                        "scraped_at": datetime.now().isoformat(),
                    }
                    self.collected_threats.append(threat_entry)
            print(
                f"[+] Successfully scraped {len(news_items)} alerts from"
                " BleepingComputer."
            )
        except Exception as e:
            print(f"[-] Error scraping BleepingComputer: {str(e)}")

    def save_to_json(self, output_file: str = "raw_threat_intel.json"):
        """Dumps collected unstructured data into JSON format for Module 2 (NER)."""
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(self.collected_threats, f, indent=4)
        print(
            f"[✔] Pipeline Stage 1 Complete: {len(self.collected_threats)} records saved to {output_file}"
        )


if __name__ == "__main__":
    scraper = ThreatIntelScraper()
    print("[*] Launching CTI Data Ingestion...")
    scraper.fetch_hacker_news(limit=2)
    scraper.fetch_bleeping_computer(limit=2)
    scraper.save_to_json()