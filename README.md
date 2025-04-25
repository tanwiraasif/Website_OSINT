# Website_OSINT
Website OSINT Tool
directory on Kali:
cd ~/projects
git init
git remote add origin <your-private-repo-url>
echo "GeoLite2-City.mmdb" > .gitignore  # Ignore the database
echo "*.png" >> .gitignore
echo "*.txt" >> .gitignore
echo "*.html" >> .gitignore
git add website_osint.py .gitignore
git commit -m "Add website_osint.py script"
git push -u origin main

Download 
GeoLite2-City.tar.gz from MaxMind, extract it to get GeoLite2-City.mmdb (50-60 MB), and place it in ~/projects/ alongside the script.The script will use it automatically.

Run the Script:
Install dependencies:

pip install requests dnspython python-whois nmap3 tldextract shodan geoip2 beautifulsoup4 builtwith sublist3r networkx matplotlib ipaddress pillow selenium
sudo apt-get install chromium-chromedriver chromiumRun:

python website_osint.pyUpdate EMAIL_PASSWORD with your Gmail App Password when ready.
