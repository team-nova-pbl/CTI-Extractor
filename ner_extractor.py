import json
import re


class ThreatNERExtractor:
    """Extracts cybersecurity entities (CVEs, Targets, Actors) from raw ingested text."""

    def __init__(self):
        # Known threat actors & common enterprise targets for dictionary/rule matching
        self.known_actors = [
            "APT28",
            "Fancy Bear",
            "Lazarus Group",
            "Volt Typhoon",
            "LockBit",
            "Sandworm",
        ]
        self.known_targets = [
            "Windows",
            "Linux",
            "Ubuntu",
            "Apache",
            "OpenSSL",
            "Exchange",
            "VMware",
        ]

    def extract_cves(self, text: str) -> list:
        """Finds CVE vulnerability patterns (e.g., CVE-2023-38831) using regular expressions."""
        pattern = r"CVE-\d{4}-\d{4,7}"
        return list(set(re.findall(pattern, text, re.IGNORECASE)))

    def extract_entities(self, input_file: str = "raw_threat_intel.json"):
        with open(input_file, "r", encoding="utf-8") as f:
            articles = json.load(f)

        processed_nodes = []
        for article in articles:
            full_text = f"{article['title']} {article['summary']}"

            found_cves = self.extract_cves(full_text)
            found_actors = [a for a in self.known_actors if a.lower() in full_text.lower()]
            found_targets = [t for t in self.known_targets if t.lower() in full_text.lower()]

            processed_nodes.append({
                "article_title": article["title"],
                "source": article["source"],
                "extracted_entities": {
                    "vulnerabilities": found_cves if found_cves else ["Unspecified CVE"],
                    "threat_actors": found_actors if found_actors else ["Unknown Actor"],
                    "targeted_assets": found_targets if found_targets else ["General Enterprise Systems"],
                },
            })

        print(f"[✔] Pipeline Stage 2 Complete: Extracted entities from {len(processed_nodes)} articles.")
        print(json.dumps(processed_nodes[:2], indent=2))


if __name__ == "__main__":
    extractor = ThreatNERExtractor()
    extractor.extract_entities()