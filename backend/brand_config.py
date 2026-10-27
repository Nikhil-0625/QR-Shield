PROTECTED_BRANDS = [
    {"name": "Paytm", "token": "paytm", "domains": ["paytm.com", "paytm.in"]},
    {"name": "PhonePe", "token": "phonepe", "domains": ["phonepe.com", "phonepe.in"]},
    {
        "name": "Google Pay",
        "token": "googlepay",
        "domains": ["pay.google.com", "google.com"],
    },
    {
        "name": "Amazon",
        "token": "amazon",
        "domains": [
            "amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazon.fr",
            "amazon.it", "amazon.es", "amazon.ca", "amazon.com.au", "amazon.co.jp",
            "amazon.com.br", "amazon.com.mx", "amazon.nl", "amazon.pl", "amazon.se",
            "amazon.ae", "amazon.sa", "amazon.sg", "amazon.eg", "amazon.com.tr"
        ]
    },
    {"name": "Flipkart", "token": "flipkart", "domains": ["flipkart.com"]},
    {
        "name": "PayPal",
        "token": "paypal",
        "domains": [
            "paypal.com", "paypal.in", "paypal.co.in", "paypal.co.uk", "paypal.de",
            "paypal.fr", "paypal.it", "paypal.es", "paypal.ca", "paypal.com.au",
            "paypal.com.br", "paypal.com.mx", "paypal.co.jp", "paypal.me"
        ]
    },
    {"name": "FedEx", "token": "fedex", "domains": ["fedex.com"]},
    {"name": "BookMyShow", "token": "bookmyshow", "domains": ["bookmyshow.com"]},
    {
        "name": "Google",
        "token": "google",
        "domains": [
            "google.com", "google.co.in", "google.co.uk", "google.de", "google.fr",
            "google.it", "google.es", "google.ca", "google.com.au", "google.co.jp",
            "google.com.br", "google.com.mx", "google.nl", "google.pl", "google.ch",
            "google.at", "google.be", "google.se", "google.no", "google.dk",
            "google.fi", "google.ie", "google.co.nz", "google.com.sg", "google.com.hk",
            "google.com.tw", "google.co.za", "google.co.id", "google.com.tr"
        ]
    },
    {"name": "Gmail", "token": "gmail", "domains": ["gmail.com", "google.com"]},
    {"name": "YouTube", "token": "youtube", "domains": ["youtube.com", "youtu.be"]},
    {
        "name": "Microsoft",
        "token": "microsoft",
        "domains": [
            "microsoft.com", "live.com", "office.com", "microsoft.co.uk", "microsoft.in",
            "microsoft.de", "microsoft.fr", "microsoft.it", "microsoft.es", "microsoft.ca",
            "microsoft.com.au", "microsoft.co.jp", "office365.com", "outlook.com",
            "bing.com", "windows.com", "msn.com", "xbox.com"
        ],
    },
    {
        "name": "Apple",
        "token": "apple",
        "domains": [
            "apple.com", "icloud.com", "apple.co.uk", "apple.in", "apple.de",
            "apple.fr", "apple.it", "apple.es", "apple.ca", "apple.com.au", "apple.co.jp"
        ]
    },
    {"name": "Facebook", "token": "facebook", "domains": ["facebook.com", "fb.com", "meta.com"]},
    {"name": "Instagram", "token": "instagram", "domains": ["instagram.com"]},
    {"name": "WhatsApp", "token": "whatsapp", "domains": ["whatsapp.com"]},
    {"name": "Twitter / X", "token": "twitter", "domains": ["twitter.com", "x.com", "t.co"]},
    {"name": "LinkedIn", "token": "linkedin", "domains": ["linkedin.com", "licdn.com"]},
    {"name": "Netflix", "token": "netflix", "domains": ["netflix.com", "netflix.net"]},
    {"name": "Myntra", "token": "myntra", "domains": ["myntra.com"]},
    {"name": "Zomato", "token": "zomato", "domains": ["zomato.com"]},
    {"name": "Swiggy", "token": "swiggy", "domains": ["swiggy.com", "swiggy.in"]},
    {
        "name": "Ola",
        "token": "ola",
        "distinctive_tokens": ["olacabs", "olaelectric"],
        "qualifiers": {"cabs", "cab", "ride", "electric", "driver", "booking", "money", "auto"},
        "requires_context": True,
        "domains": ["olacabs.com", "ola.com", "olaelectric.com"]
    },
    {"name": "Uber", "token": "uber", "domains": ["uber.com"]},
    {
        "name": "State Bank of India",
        "token": "sbi",
        "distinctive_tokens": ["onlinesbi"],
        "qualifiers": {"bank", "banking", "online", "card", "yono", "kyc", "login", "portal"},
        "requires_context": True,
        "domains": ["onlinesbi.com", "sbi.co.in", "onlinesbi.sbi", "sbi.sbi"],
    },
    {"name": "ICICI Bank", "token": "icicibank", "domains": ["icicibank.com"]},
    {"name": "HDFC Bank", "token": "hdfcbank", "domains": ["hdfcbank.com"]},
    {"name": "Axis Bank", "token": "axisbank", "domains": ["axisbank.com"]},
    {"name": "Kotak", "token": "kotak", "domains": ["kotak.com"]},
    {"name": "IRCTC", "token": "irctc", "domains": ["irctc.co.in"]},
    {"name": "UIDAI", "token": "uidai", "domains": ["uidai.gov.in"]},
    {"name": "Income Tax India", "token": "incometax", "domains": ["incometax.gov.in"]},
    {"name": "Anthropic", "token": "anthropic", "domains": ["anthropic.com"]},
    {"name": "OpenAI", "token": "openai", "domains": ["openai.com"]},
    {"name": "GitHub", "token": "github", "domains": ["github.com", "github.io"]},
    {"name": "Adobe", "token": "adobe", "domains": ["adobe.com", "adobe.co.uk", "adobe.de", "adobe.fr"]},
    {"name": "Spotify", "token": "spotify", "domains": ["spotify.com"]},
    {"name": "Hotstar", "token": "hotstar", "domains": ["hotstar.com"]},
    {"name": "Airtel", "token": "airtel", "domains": ["airtel.in"]},
    {"name": "Jio", "token": "jio", "domains": ["jio.com", "myjio.com"]},
    {
        "name": "Vodafone / Vi",
        "token": "vodafone",
        "domains": ["myvi.in", "vodafone.com"],
    },
    {"name": "HSBC", "token": "hsbc", "domains": ["hsbc.co.in", "hsbc.com"]},
    {"name": "Zerodha", "token": "zerodha", "domains": ["zerodha.com"]},
    {"name": "Groww", "token": "groww", "domains": ["groww.in"]},
    {"name": "Upstox", "token": "upstox", "domains": ["upstox.com"]},
    {"name": "Dream11", "token": "dream11", "domains": ["dream11.com"]},
    {"name": "India Post", "token": "indiapost", "domains": ["indiapost.gov.in"]},
    {"name": "EPFO", "token": "epfo", "domains": ["epfindia.gov.in"]},
    {"name": "Reddit", "token": "reddit", "domains": ["reddit.com"]},
    {"name": "Pinterest", "token": "pinterest", "domains": ["pinterest.com"]},
    {"name": "Snapchat", "token": "snapchat", "domains": ["snapchat.com"]},
    {"name": "Telegram", "token": "telegram", "domains": ["telegram.org", "t.me"]},
    {"name": "Discord", "token": "discord", "domains": ["discord.com"]},
    {"name": "Wikipedia", "token": "wikipedia", "domains": ["wikipedia.org", "wikimedia.org", "wikidata.org"]},
    {
        "name": "eBay",
        "token": "ebay",
        "domains": ["ebay.com", "ebay.co.uk", "ebay.de", "ebay.fr", "ebay.it", "ebay.es", "ebay.ca", "ebay.com.au", "ebay.in"]
    },
    {"name": "MakeMyTrip", "token": "makemytrip", "domains": ["makemytrip.com"]},
    {"name": "Goibibo", "token": "goibibo", "domains": ["goibibo.com"]},
    {"name": "Yatra", "token": "yatra", "domains": ["yatra.com"]},
    {"name": "Policybazaar", "token": "policybazaar", "domains": ["policybazaar.com"]},
    {
        "name": "LIC",
        "token": "lic",
        "distinctive_tokens": ["licindia"],
        "qualifiers": {"policy", "premium", "insurance", "portal", "login", "pay", "payment", "kyc", "online", "india"},
        "requires_context": True,
        "domains": ["licindia.in", "licindia.com", "lic.nic.in"]
    },
    {
        "name": "Bajaj Finserv",
        "token": "bajajfinserv",
        "domains": ["bajajfinserv.in"],
    },
    {
        "name": "IndiGo",
        "token": "indigo",
        "distinctive_tokens": ["goindigo"],
        "qualifiers": {"airline", "airlines", "flight", "flights", "air", "travel", "ticket", "tickets", "booking", "checkin", "webcheckin"},
        "requires_context": True,
        "domains": ["goindigo.in", "goindigo.com", "indigo.in"]
    },
    {"name": "Cash App", "token": "cashapp", "domains": ["cash.app"]},
    {"name": "Venmo", "token": "venmo", "domains": ["venmo.com"]},
    {
        "name": "Bank of America",
        "token": "bankofamerica",
        "domains": ["bankofamerica.com"],
    },
    {"name": "Wells Fargo", "token": "wellsfargo", "domains": ["wellsfargo.com"]},
    {"name": "Walmart", "token": "walmart", "domains": ["walmart.com"]},
    {
        "name": "UPS",
        "token": "ups",
        "qualifiers": {"tracking", "delivery", "parcel", "package", "shipping", "freight", "express", "post", "ship"},
        "requires_context": True,
        "domains": ["ups.com"]
    },
    {"name": "Zoom", "token": "zoom", "domains": ["zoom.us"]},
    {"name": "Dropbox", "token": "dropbox", "domains": ["dropbox.com"]},
]

LOOKALIKE_SIMILARITY_THRESHOLD = 75

MULTI_LABEL_PUBLIC_SUFFIXES = frozenset({
    "ac.in",
    "co.in",
    "com.au",
    "com.br",
    "com.in",
    "com.mx",
    "com.sg",
    "co.jp",
    "co.kr",
    "co.nz",
    "co.uk",
    "co.za",
    "gov.in",
    "org.in",
})
