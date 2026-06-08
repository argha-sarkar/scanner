import urllib.parse
import socket
import ipaddress
import ssl
import datetime
import requests
from bs4 import BeautifulSoup
from database import get_db_connection

def is_ssrf_safe(url):
    try:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False
            
        # Get IP address of target
        ip_str = socket.gethostbyname(hostname)
        ip = ipaddress.ip_address(ip_str)
        
        # Block private, loopback, link-local, multicast, etc.
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return False
        return True
    except Exception:
        return False

def check_ssl_certificate(hostname):
    issues = []
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=4) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                # Check Expiry
                exp_date_str = cert.get('notAfter')
                if exp_date_str:
                    # e.g., 'Oct 11 23:59:59 2026 GMT'
                    exp_date = datetime.datetime.strptime(exp_date_str, '%b %d %H:%M:%S %Y %Z')
                    days_remaining = (exp_date - datetime.datetime.utcnow()).days
                    if days_remaining < 0:
                        issues.append({
                            'category': 'security',
                            'title': 'SSL Certificate Expired',
                            'description': f'The SSL certificate for {hostname} expired on {exp_date_str}.',
                            'severity': 'high',
                            'remediation': 'Renew the SSL certificate immediately to prevent browser security warnings.'
                        })
                    elif days_remaining < 30:
                        issues.append({
                            'category': 'security',
                            'title': 'SSL Certificate Expiring Soon',
                            'description': f'The SSL certificate will expire in {days_remaining} days.',
                            'severity': 'medium',
                            'remediation': 'Renew the SSL certificate soon to avoid service interruption.'
                        })
    except ssl.SSLCertVerificationError as e:
        issues.append({
            'category': 'security',
            'title': 'SSL Certificate Verification Failed',
            'description': f'The SSL certificate presented by the host could not be verified. Error: {str(e)}',
            'severity': 'high',
            'remediation': 'Ensure the certificate is signed by a trusted CA, is not self-signed, and matches the domain name.'
        })
    except Exception as e:
        # Non-SSL errors (e.g. port 443 closed)
        issues.append({
            'category': 'security',
            'title': 'SSL/HTTPS Connection Failed',
            'description': f'Could not establish a secure HTTPS connection. Error: {str(e)}',
            'severity': 'high',
            'remediation': 'Enable HTTPS support on port 443 and install a valid SSL certificate.'
        })
    return issues

def run_scanner(scan_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT target_url FROM scans WHERE id = ?', (scan_id,))
    scan = cursor.fetchone()
    if not scan:
        conn.close()
        return
        
    url = scan['target_url']
    
    # 1. SSRF Safety Check
    if not is_ssrf_safe(url):
        cursor.execute(
            "UPDATE scans SET status = 'failed' WHERE id = ?",
            (scan_id,)
        )
        cursor.execute(
            "INSERT INTO scan_issues (scan_id, category, title, description, severity, remediation) VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, 'security', 'SSRF Protection Blocked Request', 
             'The scan was aborted because the target URL resolved to a private or loopback IP address.', 
             'high', 'Provide a public, reachable domain name or IP address for scanning.')
        )
        conn.commit()
        conn.close()
        return
        
    # Update status to scanning
    cursor.execute("UPDATE scans SET status = 'scanning' WHERE id = ?", (scan_id,))
    conn.commit()
    
    issues = []
    
    try:
        parsed_url = urllib.parse.urlparse(url)
        hostname = parsed_url.hostname
        scheme = parsed_url.scheme
        
        # 2. Scheme check
        if scheme == 'http':
            issues.append({
                'category': 'security',
                'title': 'Unencrypted Connection (HTTP)',
                'description': 'The target website is serving content over unencrypted HTTP protocol.',
                'severity': 'high',
                'remediation': 'Redirect all HTTP traffic to HTTPS on port 443 and install a valid SSL certificate.'
            })
            
        # 3. SSL Check
        if hostname:
            ssl_issues = check_ssl_certificate(hostname)
            issues.extend(ssl_issues)
            
        # 4. HTTP Headers and HTML Content check
        start_time = datetime.datetime.now()
        headers = {
            'User-Agent': 'AegisScan Bot/1.0 (Web Security Scanner)'
        }
        
        response = requests.get(url, headers=headers, timeout=8, allow_redirects=True)
        latency = (datetime.datetime.now() - start_time).total_seconds()
        
        # Latency check
        if latency > 2.0:
            issues.append({
                'category': 'performance',
                'title': 'Slow Server Response Latency',
                'description': f'Initial load took {latency:.2f} seconds, which is higher than the recommended threshold of 1.5 seconds.',
                'severity': 'medium',
                'remediation': 'Optimize server configurations, leverage caching mechanisms, and check network bandwidth.'
            })
        elif latency > 1.0:
            issues.append({
                'category': 'performance',
                'title': 'Moderate Server Latency',
                'description': f'The initial page load took {latency:.2f} seconds.',
                'severity': 'low',
                'remediation': 'Consider compressing assets or tuning your server cache parameters.'
            })
            
        # Security headers
        resp_headers = response.headers
        
        # CSP
        if 'Content-Security-Policy' not in resp_headers:
            issues.append({
                'category': 'security',
                'title': 'Content Security Policy (CSP) Missing',
                'description': 'The website does not restrict resources (scripts, stylesheets, etc.) that can be loaded using Content-Security-Policy.',
                'severity': 'high',
                'remediation': 'Define a robust Content-Security-Policy header to prevent Cross-Site Scripting (XSS) and injection attacks.'
            })
            
        # HSTS (Strict-Transport-Security)
        if 'Strict-Transport-Security' not in resp_headers and scheme == 'https':
            issues.append({
                'category': 'security',
                'title': 'HTTP Strict Transport Security (HSTS) Missing',
                'description': 'The website does not enforce HTTPS connections using HSTS header.',
                'severity': 'medium',
                'remediation': 'Implement the Strict-Transport-Security header to force modern browsers to communicate solely over HTTPS.'
            })
            
        # X-Frame-Options
        if 'X-Frame-Options' not in resp_headers and 'frame-ancestors' not in resp_headers.get('Content-Security-Policy', ''):
            issues.append({
                'category': 'security',
                'title': 'X-Frame-Options Header Missing',
                'description': 'Without this header, this page can be loaded inside an iframe, making it vulnerable to Clickjacking.',
                'severity': 'medium',
                'remediation': 'Set the X-Frame-Options header to DENY or SAMEORIGIN.'
            })
            
        # X-Content-Type-Options
        if 'X-Content-Type-Options' not in resp_headers:
            issues.append({
                'category': 'security',
                'title': 'X-Content-Type-Options Header Missing',
                'description': 'Missing nosniff flag, allowing browsers to MIME-sniff style or script assets incorrectly.',
                'severity': 'low',
                'remediation': 'Set the X-Content-Type-Options header to "nosniff".'
            })
            
        # Referrer-Policy
        if 'Referrer-Policy' not in resp_headers:
            issues.append({
                'category': 'security',
                'title': 'Referrer-Policy Header Missing',
                'description': 'No Referrer-Policy header is configured, which could lead to sensitive navigation tokens leaking to external domains.',
                'severity': 'low',
                'remediation': 'Set the Referrer-Policy header to "no-referrer-when-downgrade" or "strict-origin-when-cross-origin".'
            })
            
        # Server signature disclosures
        server_header = resp_headers.get('Server')
        x_powered_by = resp_headers.get('X-Powered-By')
        if server_header:
            issues.append({
                'category': 'security',
                'title': 'Server Signature Header Leak',
                'description': f'The HTTP response headers disclose information about the server: "{server_header}".',
                'severity': 'low',
                'remediation': 'Configure the web server to disable server signatures (e.g. ServerTokens ProductOnly or ServerSignature Off in Apache).'
            })
        if x_powered_by:
            issues.append({
                'category': 'security',
                'title': 'X-Powered-By Header Disclosed',
                'description': f'The technology stack is exposed via the X-Powered-By header: "{x_powered_by}".',
                'severity': 'low',
                'remediation': 'Configure your application server to suppress the X-Powered-By header.'
            })
            
        # 5. HTML Content & SEO checks
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Page Title check
        title_tag = soup.find('title')
        if not title_tag or not title_tag.text.strip():
            issues.append({
                'category': 'seo',
                'title': 'Missing HTML Title Tag',
                'description': 'The page does not have a valid HTML title tag, affecting browser tabs and search engine results.',
                'severity': 'medium',
                'remediation': 'Add a descriptive <title> tag within the <head> block of the webpage.'
            })
            
        # Meta Description check
        meta_desc = soup.find('meta', attrs={'name': 'description'})
        if not meta_desc or not meta_desc.get('content', '').strip():
            issues.append({
                'category': 'seo',
                'title': 'Missing Meta Description',
                'description': 'No meta description was found, which negatively affects Search Engine Optimization (SEO) previews.',
                'severity': 'low',
                'remediation': 'Add a <meta name="description" content="..."> tag to summarize page content.'
            })
            
        # Image Alt Tags
        images = soup.find_all('img')
        missing_alt = 0
        for img in images:
            if not img.get('alt') or not img.get('alt', '').strip():
                missing_alt += 1
                
        if missing_alt > 0:
            issues.append({
                'category': 'best_practices',
                'title': 'Images Missing Alt Attributes',
                'description': f'Found {missing_alt} image(s) on the page that do not have an alt text attribute.',
                'severity': 'low',
                'remediation': 'Add descriptive "alt" attributes to all <img> tags to improve accessibility (WCAG) and search indexing.'
            })
            
        # Broken link testing (sample first 10 absolute or relative links)
        links = soup.find_all('a', href=True)
        broken_count = 0
        tested = 0
        for link in links:
            href = link.get('href')
            # Resolve relative URLs
            full_link = urllib.parse.urljoin(url, href)
            
            # Filter standard HTTP/HTTPS links
            parsed_link = urllib.parse.urlparse(full_link)
            if parsed_link.scheme not in ('http', 'https'):
                continue
                
            # Restrict to first 10 checks to keep scans fast
            tested += 1
            if tested > 10:
                break
                
            try:
                # Do a HEAD request to check link status
                link_resp = requests.head(full_link, headers=headers, timeout=3, allow_redirects=True)
                if link_resp.status_code >= 400:
                    broken_count += 1
            except Exception:
                broken_count += 1
                
        if broken_count > 0:
            issues.append({
                'category': 'best_practices',
                'title': 'Broken Links Found',
                'description': f'We identified {broken_count} broken links pointing to unavailable pages or resources.',
                'severity': 'medium',
                'remediation': 'Audit the anchor (<a>) links on the page and remove or correct any pointing to non-existent URLs.'
            })

    except Exception as e:
        issues.append({
            'category': 'security',
            'title': 'Web Scan Interrupted',
            'description': f'An unexpected error interrupted the scanner. Error: {str(e)}',
            'severity': 'high',
            'remediation': 'Ensure the target website is public, responsive, and not blocking automated requests.'
        })

    # 6. Calculate Score
    score = 100
    high_count = 0
    medium_count = 0
    low_count = 0
    
    for issue in issues:
        if issue['severity'] == 'high':
            score -= 20
            high_count += 1
        elif issue['severity'] == 'medium':
            score -= 10
            medium_count += 1
        elif issue['severity'] == 'low':
            score -= 5
            low_count += 1
            
    # Clamp score
    score = max(0, min(100, score))
    
    # Save issues and updates
    for issue in issues:
        cursor.execute(
            'INSERT INTO scan_issues (scan_id, category, title, description, severity, remediation) VALUES (?, ?, ?, ?, ?, ?)',
            (scan_id, issue['category'], issue['title'], issue['description'], issue['severity'], issue['remediation'])
        )
        
    cursor.execute('''
        UPDATE scans 
        SET status = 'completed', score = ?, vuln_count_high = ?, vuln_count_medium = ?, vuln_count_low = ?
        WHERE id = ?
    ''', (score, high_count, medium_count, low_count, scan_id))
    
    conn.commit()
    conn.close()
