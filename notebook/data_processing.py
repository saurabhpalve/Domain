import re
import ipaddress
import tldextract
import pandas as pd
from pathlib import Path
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from concurrent.futures import ProcessPoolExecutor


def safe_get_tld(url: str) -> str:
    try:
        ext = tldextract.extract(url)
        return ext.suffix if ext.suffix else 'no tld'
    except Exception:
        return 'no tld'  # fallback if no valid TLD found

def is_domain_IP_check(url:str):
    try:
        hostname = urlparse(url).hostname
        if hostname is None:
            return 1
        # Check if hostname is IP address
        ipaddress.ip_address(hostname)
        return 1  # It's an IP address
    except ValueError:
        return 0  # Not an IP, so assume domain

def subdomain_count(url: str) -> int:
    if is_domain_IP_check(url) == 0:
        ext = tldextract.extract(url)
        # ext.subdomain is a string of subdomains separated by dots
        if ext.subdomain:
            # Count the levels in the subdomain by splitting on '.'
            return len(ext.subdomain.split('.'))
        else:
            return 0
    else:
        return 0
    
def count_obfuscated_chars(url: str) -> int:
    specials = '@!$&*+;=?#[\\](){}%'
    count = sum(url.count(c) for c in specials)
    count += len(re.findall(r'%[0-9A-Fa-f]{2}', url))
    return count

def check_html(filename: str, url: str):
    DATA_DIR = Path.cwd() / "data" / "html data"
    file_path = DATA_DIR / filename
    suspicious_terms = [
        'bank', 'pay', 'crypto', 
        "user id", "customer id", "account number", 
        "password", "pin", "ipin",
        "otp", "one-time password", "credit/ debit card number",
        "cvv/ cvc", "expiry date", "atm card number", 
        "date of birth", "dob", "address", 
        "full name", "pincode", "zip code",
    ]

    if not file_path.exists():
        return (0,) * 11
    try:
        text = file_path.read_text(encoding="utf-8", errors="ignore")
        soup = BeautifulSoup(text, "lxml")
    except Exception:
        return (0,) * 11

    parsed_domain = urlparse(url).netloc
    has_title = int(bool(soup.title and soup.title.string and soup.title.string.strip())) # Checks for title
    has_desc = int(bool(soup.find("meta", attrs={"name": "description"}))) # Checks for description
    has_external_form = int(any(
        urlparse(urljoin(url, form.get("action", ""))).netloc != parsed_domain
        for form in soup.select("form[action]")
    )) # Checks for external_form
    icon_link = soup.find("link", rel=lambda x: x and "icon" in x.lower())
    has_favicon = int(bool(icon_link and icon_link.get("href"))) # Checks for favicon
    no_of_images = len(soup.find_all("img")) # Checks for number of images
    no_of_js = len(soup.find_all("script")) # Checks for number of JavaScript
    has_password_field = int(bool(soup.find("input", attrs= {"type": "password", "id": "password", "name": "password"}))) # Checks for Password field
    has_submit_button = int(
        bool(
            soup.find("input", attrs= {"type": "submit", "value": "Submit Form"}) 
            or soup.find("button", attrs= {"type": "submit"})
        )
    ) # Checks for the submit button
    symbol = u'\N{COPYRIGHT SIGN}'.encode('utf-8')
    symbol = symbol.decode('utf-8')
    pattern = r'' + symbol
    has_copyright_info = int(bool(soup.find_all(string=re.compile(pattern=pattern)))) # Checks for the Copyright 
    has_hidden_field = 1 if soup.find_all("input", type="hidden") else 0 # Checks for hidden fields
    text = soup.get_text(separator=' ', strip=True).lower()
    found_terms = [term for term in suspicious_terms if term in text]
    no_financial_terms = len(found_terms) # Checks and give financial terms 
    return (
        has_title, has_desc, has_external_form, 
        has_favicon, no_of_images, no_of_js, 
        has_password_field, has_copyright_info, has_hidden_field, 
        no_financial_terms, has_submit_button
    )

def run_checks(df: pd.DataFrame, workers=14):
    with ProcessPoolExecutor(max_workers=workers) as executor:
        results = list(executor.map(check_html, df["website"], df["url"]))
    df[[
        "has_title", "has_description", 
        "has_external_form_submit", "has_favicon", 
        "no_of_images", "no_of_js", "has_password_field", 
        "has_copyright_info", "has_hidden_field",
        "no_financial_terms", "has_submit_button"
    ]] = results
    return df



if __name__ == "__main__":
    
    index_csv_path = Path.cwd() / "data" / "index.csv" 
    print(index_csv_path)
    index_df = pd.read_csv(index_csv_path)

    print("starting url feature extract")
    index_df = index_df.assign(
        tld=index_df['url'].apply(safe_get_tld),
        url_len=index_df['url'].str.len(),
        is_domain_IP=index_df['url'].apply(is_domain_IP_check),
        no_of_sub_domain=index_df['url'].apply(subdomain_count),
        no_of_obfuscated_chars=index_df['url'].apply(count_obfuscated_chars),
        is_https=index_df['url'].apply(lambda u: urlparse(u).scheme == 'https').astype(int),
        no_equal=index_df['url'].str.count('='),
        no_qmark=index_df['url'].str.count(r'\?'),
        no_amp=index_df['url'].str.count('&'),
        no_dot=index_df['url'].str.count('.'),
        no_underlines=index_df['url'].str.count('_'),
        no_exclamation=index_df['url'].str.count('!'),
        no_tilde=index_df['url'].str.count('~'),
        no_vowels=index_df['url'].str.count(r'[aeiouAEIOU]')
    )
    print("url feature extract completed")

    print("starting HTML feature extract")
    index_df = run_checks(index_df, workers=30)
    print("HTML feature extrac complete")

    index_df.to_csv(Path.cwd() / "data" / "index feature extract.csv", index=False)
    print("created csv file")