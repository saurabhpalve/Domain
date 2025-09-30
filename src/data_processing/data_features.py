import re
from typing import Literal
import requests
import ipaddress
import tldextract
import pandas as pd
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

class URLFeatureExtraction:
    def __init__(self, url:str) -> None:
        self.url = url
    
    def _safe_get_tld(self) -> str:
        try:
            ext = tldextract.extract(self.url)
            return ext.suffix if ext.suffix else 'no tld'
        except Exception:
            return 'no tld'  # fallback if no valid TLD found
    
    def _is_domain_IP_check(self) -> Literal[1] | Literal[0]:
        try:
            hostname = urlparse(self.url).hostname
            # Treat None hostname as IP by returning 1 directly
            ipaddress.ip_address(hostname)  # Will raise ValueError if not an IP
            return 1  # It's an IP address
        except ValueError:
            return 0  # Not an IP, so assume domain
    
    def _subdomain_count(self) -> int:
        try:
            ext = tldextract.extract(self.url)
            return len(ext.subdomain.split('.')) if ext.subdomain else 0
        except Exception:
            pass
        return 0
    
    def _count_obfuscated_chars(self) -> int:
        pattern = r'[@!$&*+;=?#\[\](){}%]|%[0-9A-Fa-f]{2}'
        matches = re.findall(pattern, self.url)
        return len(matches)
    
    def features(self) -> pd.DataFrame:
        data = {
            "tld": self._safe_get_tld(),
            "url_len": len(self.url),
            "is_domain_IP": self._is_domain_IP_check(),
            "no_of_sub_domain": self._subdomain_count(),
            "no_of_obfuscated_chars": self._count_obfuscated_chars(),
            "is_https": int(urlparse(self.url).scheme == 'https'),
            "no_equal": self.url.count('='),
            "no_qmark": self.url.count(r'\?'),
            "no_amp": self.url.count('&'),
            "no_dot": self.url.count('.'),
            "no_underlines": self.url.count('_'),
            "no_exclamation": self.url.count('!'),
            "no_tilde": self.url.count('~'),
            "no_vowels": self.url.count(r'[aeiouAEIOU]'),
        }
        return pd.DataFrame([data])


class HTMLFeatureExtract:
    def __init__(self, url:str) -> None:
        self.url = url

    def _get_html_text(self) -> str:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)"
                        " Chrome/116.0.0.0 Safari/537.36",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive"
        }
        response = requests.get(url=self.url, headers=headers)
        if response.status_code != 200:
            raise "Page not found, Cannot get the HTML data"
        return response.text

    def features(self) -> pd.DataFrame:
        columns = [
            "has_title", "has_description", "has_external_form_submit", "has_favicon",
            "no_of_images", "no_of_js", "has_password_field", "has_copyright_info",
            "has_hidden_field", "no_financial_terms", "has_submit_button"
        ]
        suspicious_terms = [
            'bank', 'pay', 'crypto', "user id", "customer id", "account number",
            "password", "pin", "ipin", "otp", "one-time password", "credit/ debit card number",
            "cvv/ cvc", "expiry date", "atm card number", "date of birth", "dob", "address",
            "full name", "pincode", "zip code",
        ]

        try:
            text = self._get_html_text()
            soup = BeautifulSoup(text, "lxml")
        except Exception:
            return pd.DataFrame([[0]*len(columns)], columns=columns)

        parsed_domain = urlparse(self.url).netloc

        def has_element(selector):
            return bool(soup.select_one(selector))

        def external_form_exists():
            return any(
                urlparse(urljoin(self.url, form.get("action", ""))).netloc != parsed_domain
                for form in soup.select("form[action]")
            )

        icon_link = soup.find("link", rel=lambda x: x and "icon" in x.lower())
        text = soup.get_text(separator=' ', strip=True).lower()
        found_terms_count = sum(term in text for term in suspicious_terms)

        data = {
            "has_title": int(bool(soup.title and soup.title.string and soup.title.string.strip())),
            "has_description": int(bool(soup.find("meta", attrs={"name": "description"}))),
            "has_external_form_submit": int(external_form_exists()),
            "has_favicon": int(bool(icon_link and icon_link.get("href"))),
            "no_of_images": len(soup.find_all("img")),
            "no_of_js": len(soup.find_all("script")),
            "has_password_field": int(has_element('input[type="password"][name="password"]')),
            "has_submit_button": int(bool(has_element('input[type="submit"][value="Submit Form"]') or has_element('button[type="submit"]'))),
            "has_copyright_info": int(bool(soup.find_all(string=re.compile(r'\u00A9')))),
            "has_hidden_field": int(bool(soup.find_all("input", type="hidden"))),
            "no_financial_terms": found_terms_count
        }

        return pd.DataFrame([data], columns=columns)



    
class URLFeatures(pd.DataFrame):
    def __new__(cls, url: str) -> pd.DataFrame:
        url_features = URLFeatureExtraction(url).features()
        html_features = HTMLFeatureExtract(url).features()
        combined = pd.concat([url_features, html_features], axis=1)
        # Return combined DataFrame as instance
        return combined

if __name__ == "__main__":
    df = URLFeatures(url="https://www.youtube.com/watch?v=gdNknCDf2LU")
    print(df)