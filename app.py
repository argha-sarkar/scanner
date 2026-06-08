from flask import Flask, render_template, redirect, url_for, request, session, flash, Response
from database import get_db_connection, init_db
from auth import auth_bp, login_required
from scanner import run_scanner, is_ssrf_safe
import threading
import csv
import io
from functools import wraps

app = Flask(__name__)
app.secret_key = 'aegis_scan_secure_developer_key_2026'

# OWASP Mitigation: Secure session cookie configurations
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=1800 # 30 minutes active session limit
)

# Register blueprints
app.register_blueprint(auth_bp, url_prefix='/auth')

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('auth.login'))

@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get recent scans
    cursor.execute(
        'SELECT * FROM scans WHERE user_id = ? ORDER BY created_at DESC LIMIT 10',
        (user_id,)
    )
    scans = cursor.fetchall()
    
    # Calculate stats
    cursor.execute(
        'SELECT COUNT(*) as total, AVG(score) as avg_score, SUM(vuln_count_high) as total_high FROM scans WHERE user_id = ? AND status = "completed"',
        (user_id,)
    )
    stats = cursor.fetchone()
    
    metrics = {
        'total_scans': stats['total'] if stats['total'] else 0,
        'avg_score': stats['avg_score'] if stats['avg_score'] else 100.0,
        'total_high_vulns': stats['total_high'] if stats['total_high'] else 0
    }
    
    # Check if there are active scans
    cursor.execute(
        'SELECT COUNT(*) FROM scans WHERE user_id = ? AND status IN ("pending", "scanning")',
        (user_id,)
    )
    active_scans_count = cursor.fetchone()[0]
    active_scans_exist = active_scans_count > 0
    
    conn.close()
    
    return render_template(
        'dashboard.html',
        scans=scans,
        metrics=metrics,
        active_scans_exist=active_scans_exist,
        active_page='dashboard'
    )

@app.route('/scan/trigger', methods=['POST'])
@login_required
def trigger_scan():
    target_url = request.form.get('target_url', '').strip()
    user_id = session['user_id']
    
    if not target_url:
        flash('Target URL is required.', 'danger')
        return redirect(url_for('dashboard'))
        
    # Basic scheme checks
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
        
    # Block internal scans immediately to prevent SSRF
    if not is_ssrf_safe(target_url):
        flash('SSRF Protection: Scans targeting private, local, or loopback network addresses are blocked.', 'danger')
        return redirect(url_for('dashboard'))
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Insert new scan record as pending
    cursor.execute(
        'INSERT INTO scans (user_id, target_url, status) VALUES (?, ?, ?)',
        (user_id, target_url, 'pending')
    )
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    # Start scan thread asynchronously to prevent blocking the UI
    scan_thread = threading.Thread(target=run_scanner, args=(scan_id,))
    scan_thread.daemon = True
    scan_thread.start()
    
    flash('Scan initiated successfully! Tracking progress below.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/report/<int:scan_id>')
@login_required
def view_report(scan_id):
    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Secure ownership verification (IDOR protection)
    cursor.execute('SELECT * FROM scans WHERE id = ? AND user_id = ?', (scan_id, user_id))
    scan = cursor.fetchone()
    
    if not scan:
        conn.close()
        flash('Report not found or permission denied.', 'danger')
        return redirect(url_for('dashboard'))
        
    # Get scan issues
    cursor.execute('SELECT * FROM scan_issues WHERE scan_id = ?', (scan_id,))
    issues = cursor.fetchall()
    
    # Fetch comments and tasks mapping
    issues_with_collab = []
    for issue in issues:
        cursor.execute(
            'SELECT * FROM comments WHERE finding_id = ? AND finding_type = "scan" ORDER BY created_at ASC',
            (issue['id'],)
        )
        comments = [dict(c) for c in cursor.fetchall()]
        
        cursor.execute(
            'SELECT * FROM tasks WHERE finding_id = ? AND finding_type = "scan" LIMIT 1',
            (issue['id'],)
        )
        task = cursor.fetchone()
        task_dict = dict(task) if task else {'assigned_to': '', 'status': 'Open'}
        
        issue_dict = dict(issue)
        issue_dict['comments'] = comments
        issue_dict['task'] = task_dict
        issues_with_collab.append(issue_dict)
        
    conn.close()
    
    return render_template('report.html', scan=scan, issues=issues_with_collab)

@app.route('/report/<int:scan_id>/export')
@login_required
def export_report(scan_id):
    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Secure ownership verification (IDOR protection)
    cursor.execute('SELECT * FROM scans WHERE id = ? AND user_id = ?', (scan_id, user_id))
    scan = cursor.fetchone()
    
    if not scan:
        conn.close()
        return "Permission denied", 403
        
    cursor.execute('SELECT * FROM scan_issues WHERE scan_id = ?', (scan_id,))
    issues = cursor.fetchall()
    conn.close()
    
    # Generate CSV response
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Header
    writer.writerow(['Category', 'Title', 'Severity', 'Description', 'Remediation'])
    
    for issue in issues:
        writer.writerow([
            issue['category'],
            issue['title'],
            issue['severity'],
            issue['description'],
            issue['remediation']
        ])
        
    csv_data = output.getvalue()
    
    # Clean target name for file title
    clean_target = scan['target_url'].replace('https://', '').replace('http://', '').replace('/', '_')
    filename = f"aegisscan_report_{clean_target}_{scan['id']}.csv"
    
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-disposition": f"attachment; filename={filename}"}
    )

@app.route('/history')
@login_required
def history():
    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        'SELECT * FROM scans WHERE user_id = ? ORDER BY created_at DESC',
        (user_id,)
    )
    scans = cursor.fetchall()
    conn.close()
    
    return render_template('history.html', scans=scans, active_page='history')

@app.route('/scan/delete/<int:scan_id>', methods=['POST'])
@login_required
def delete_scan(scan_id):
    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Verify ownership before deletion
    cursor.execute('SELECT id FROM scans WHERE id = ? AND user_id = ?', (scan_id, user_id))
    scan = cursor.fetchone()
    
    if scan:
        cursor.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
        conn.commit()
        flash('Scan history record deleted.', 'success')
    else:
        flash('Record not found or permission denied.', 'danger')
        
    conn.close()
    return redirect(url_for('history'))

@app.route('/compare')
@login_required
def compare():
    user_id = session['user_id']
    scan_a_id = request.args.get('scan_a')
    scan_b_id = request.args.get('scan_b')
    
    if not scan_a_id or not scan_b_id:
        flash('Please select two scans to compare.', 'danger')
        return redirect(url_for('history'))
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Ownership checks
    cursor.execute('SELECT * FROM scans WHERE id = ? AND user_id = ?', (scan_a_id, user_id))
    scan_a = cursor.fetchone()
    cursor.execute('SELECT * FROM scans WHERE id = ? AND user_id = ?', (scan_b_id, user_id))
    scan_b = cursor.fetchone()
    
    if not scan_a or not scan_b:
        conn.close()
        flash('Permission denied or scans not found.', 'danger')
        return redirect(url_for('history'))
        
    # Get issues for scan A
    cursor.execute('SELECT title, description, severity, category FROM scan_issues WHERE scan_id = ?', (scan_a_id,))
    issues_a = [dict(ix) for ix in cursor.fetchall()]
    
    # Get issues for scan B
    cursor.execute('SELECT title, description, severity, category FROM scan_issues WHERE scan_id = ?', (scan_b_id,))
    issues_b = [dict(ix) for ix in cursor.fetchall()]
    
    conn.close()
    
    # Compare
    titles_a = {issue['title'] for issue in issues_a}
    titles_b = {issue['title'] for issue in issues_b}
    
    new_issues = [issue for issue in issues_b if issue['title'] not in titles_a]
    resolved_issues = [issue for issue in issues_a if issue['title'] not in titles_b]
    constant_issues = [issue for issue in issues_b if issue['title'] in titles_a]
    
    return render_template(
        'compare.html',
        scan_a=scan_a,
        scan_b=scan_b,
        new_issues=new_issues,
        resolved_issues=resolved_issues,
        constant_issues=constant_issues
    )

@app.route('/kb')
@login_required
def kb():
    return render_template('kb.html', active_page='kb')

from flask import jsonify

@app.route('/api/scans')
@login_required
def api_scans():
    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id, target_url, status, score, created_at FROM scans WHERE user_id = ? ORDER BY created_at DESC', (user_id,))
    scans = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(scans)

@app.route('/api/report/<int:scan_id>')
@login_required
def api_report(scan_id):
    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM scans WHERE id = ? AND user_id = ?', (scan_id, user_id))
    scan = cursor.fetchone()
    if not scan:
        conn.close()
        return jsonify({'error': 'Scan not found or unauthorized'}), 403
    cursor.execute('SELECT id, category, title, description, severity, remediation FROM scan_issues WHERE scan_id = ?', (scan_id,))
    issues = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify({
        'scan': dict(scan),
        'issues': issues
    })

from sast_engine import analyze_code

@app.route('/sast', methods=['GET', 'POST'])
@login_required
def sast_dashboard():
    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get recent SAST scans
    cursor.execute('SELECT * FROM sast_scans WHERE user_id = ? ORDER BY created_at DESC LIMIT 10', (user_id,))
    sast_scans = cursor.fetchall()
    
    # Calculate SAST stats
    cursor.execute('SELECT COUNT(*) as total, AVG(score) as avg_score FROM sast_scans WHERE user_id = ?', (user_id,))
    stats = cursor.fetchone()
    
    sast_metrics = {
        'total_scans': stats['total'] if stats['total'] else 0,
        'avg_score': stats['avg_score'] if stats['avg_score'] else 100.0
    }
    
    conn.close()
    return render_template(
        'sast.html',
        sast_scans=sast_scans,
        metrics=sast_metrics,
        active_page='sast'
    )

@app.route('/sast/scan', methods=['POST'])
@login_required
def trigger_sast_scan():
    user_id = session['user_id']
    source_code = request.form.get('source_code', '').strip()
    uploaded_file = request.files.get('code_file')
    filename = 'snippet.py'
    
    # If file uploaded, read it
    if uploaded_file and uploaded_file.filename:
        filename = uploaded_file.filename
        source_code = uploaded_file.read().decode('utf-8', errors='ignore')
        
    if not source_code:
        flash('Please paste some code or upload a Python script to scan.', 'danger')
        return redirect(url_for('sast_dashboard'))
        
    # Analyze
    findings, score = analyze_code(source_code)
    
    # Track vulnerability counts by severity
    high = sum(1 for f in findings if f['severity'] == 'high')
    medium = sum(1 for f in findings if f['severity'] == 'medium')
    low = sum(1 for f in findings if f['severity'] == 'low')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO sast_scans (user_id, filename, source_code, score, vuln_count_high, vuln_count_medium, vuln_count_low)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (user_id, filename, source_code, score, high, medium, low))
    sast_id = cursor.lastrowid
    
    # Add issues
    for f in findings:
        cursor.execute('''
            INSERT INTO sast_issues (sast_id, line_number, category, title, description, severity, remediation, code_line)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (sast_id, f['line_number'], f['category'], f['title'], f['description'], f['severity'], f['remediation'], f['code_line']))
        
    conn.commit()
    conn.close()
    
    flash('Code analysis completed successfully!', 'success')
    return redirect(url_for('view_sast_report', sast_id=sast_id))

@app.route('/sast/report/<int:sast_id>')
@login_required
def view_sast_report(sast_id):
    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Validate ownership
    cursor.execute('SELECT * FROM sast_scans WHERE id = ? AND user_id = ?', (sast_id, user_id))
    scan = cursor.fetchone()
    
    if not scan:
        conn.close()
        flash('Code report not found or permission denied.', 'danger')
        return redirect(url_for('sast_dashboard'))
        
    # Get issues
    cursor.execute('SELECT * FROM sast_issues WHERE sast_id = ? ORDER BY line_number ASC', (sast_id,))
    issues = cursor.fetchall()
    
    # Fetch comments and tasks mapping
    issues_with_collab = []
    for issue in issues:
        cursor.execute(
            'SELECT * FROM comments WHERE finding_id = ? AND finding_type = "sast" ORDER BY created_at ASC',
            (issue['id'],)
        )
        comments = [dict(c) for c in cursor.fetchall()]
        
        cursor.execute(
            'SELECT * FROM tasks WHERE finding_id = ? AND finding_type = "sast" LIMIT 1',
            (issue['id'],)
        )
        task = cursor.fetchone()
        task_dict = dict(task) if task else {'assigned_to': '', 'status': 'Open'}
        
        issue_dict = dict(issue)
        issue_dict['comments'] = comments
        issue_dict['task'] = task_dict
        issues_with_collab.append(issue_dict)
        
    conn.close()
    
    # Format source code with line numbers for rendering
    code_lines = scan['source_code'].splitlines()
    formatted_code = [{'number': i + 1, 'text': line} for i, line in enumerate(code_lines)]
    
    return render_template('sast_report.html', scan=scan, issues=issues_with_collab, formatted_code=formatted_code, active_page='sast')

@app.route('/sast/delete/<int:sast_id>', methods=['POST'])
@login_required
def delete_sast_scan(sast_id):
    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Verify ownership
    cursor.execute('SELECT id FROM sast_scans WHERE id = ? AND user_id = ?', (sast_id, user_id))
    scan = cursor.fetchone()
    
    if scan:
        cursor.execute('DELETE FROM sast_scans WHERE id = ?', (sast_id,))
        conn.commit()
        flash('Code scan record deleted.', 'success')
    else:
        flash('Record not found or permission denied.', 'danger')
        
    conn.close()
    return redirect(url_for('sast_dashboard'))

import secrets
import hashlib

@app.route('/assets')
@login_required
def view_assets():
    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Query assets
    cursor.execute('SELECT * FROM assets WHERE user_id = ? ORDER BY created_at DESC', (user_id,))
    assets = cursor.fetchall()
    
    # Query API keys
    cursor.execute('SELECT * FROM api_keys WHERE user_id = ? ORDER BY created_at DESC', (user_id,))
    api_keys = cursor.fetchall()
    
    conn.close()
    
    # Check if there is a newly generated API key in session
    new_api_key = session.pop('new_api_key', None)
    
    return render_template(
        'assets.html',
        assets=assets,
        api_keys=api_keys,
        new_api_key=new_api_key,
        active_page='assets'
    )

@app.route('/assets/add', methods=['POST'])
@login_required
def add_asset():
    user_id = session['user_id']
    name = request.form.get('name', '').strip()
    asset_type = request.form.get('type', 'Web Domain')
    tags = request.form.get('tags', '').strip()
    
    if not name:
        flash('Asset name is required.', 'danger')
        return redirect(url_for('view_assets'))
        
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO assets (user_id, name, type, tags) VALUES (?, ?, ?, ?)',
        (user_id, name, asset_type, tags)
    )
    conn.commit()
    conn.close()
    
    flash('Asset registered successfully.', 'success')
    return redirect(url_for('view_assets'))

@app.route('/assets/delete/<int:asset_id>', methods=['POST'])
@login_required
def delete_asset(asset_id):
    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Verify ownership
    cursor.execute('SELECT id FROM assets WHERE id = ? AND user_id = ?', (asset_id, user_id))
    asset = cursor.fetchone()
    
    if asset:
        cursor.execute('DELETE FROM assets WHERE id = ?', (asset_id,))
        conn.commit()
        flash('Asset removed from inventory.', 'success')
    else:
        flash('Asset not found or permission denied.', 'danger')
        
    conn.close()
    return redirect(url_for('view_assets'))

@app.route('/api-key/add', methods=['POST'])
@login_required
def add_api_key():
    user_id = session['user_id']
    name = request.form.get('name', '').strip()
    
    if not name:
        flash('Integration name is required.', 'danger')
        return redirect(url_for('view_assets'))
        
    # Generate API key token (48 chars hex)
    token = secrets.token_hex(24)
    # Hash token using SHA-256 for secure database matching
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO api_keys (user_id, key_value, name) VALUES (?, ?, ?)',
        (user_id, token_hash, name)
    )
    conn.commit()
    conn.close()
    
    # Save the original token value in session to show once
    session['new_api_key'] = token
    
    flash('API Access Token generated successfully.', 'success')
    return redirect(url_for('view_assets'))

@app.route('/api-key/delete/<int:key_id>', methods=['POST'])
@login_required
def delete_api_key(key_id):
    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Verify ownership
    cursor.execute('SELECT id FROM api_keys WHERE id = ? AND user_id = ?', (key_id, user_id))
    key = cursor.fetchone()
    
    if key:
        cursor.execute('DELETE FROM api_keys WHERE id = ?', (key_id,))
        conn.commit()
        flash('API access token revoked successfully.', 'success')
    else:
        flash('Token record not found or permission denied.', 'danger')
        
    conn.close()
    return redirect(url_for('view_assets'))

@app.route('/finding/<string:finding_type>/<int:finding_id>/comment', methods=['POST'])
@login_required
def add_finding_comment(finding_type, finding_id):
    user_id = session['user_id']
    username = session['username']
    text = request.form.get('text', '').strip()
    redirect_url = request.form.get('redirect_url', '')
    
    if not text:
        flash('Comment text cannot be empty.', 'danger')
        return redirect(redirect_url or url_for('dashboard'))
        
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO comments (finding_id, finding_type, user_id, username, text) VALUES (?, ?, ?, ?, ?)',
        (finding_id, finding_type, user_id, username, text)
    )
    conn.commit()
    conn.close()
    
    flash('Comment posted.', 'success')
    return redirect(redirect_url or url_for('dashboard'))

@app.route('/finding/<string:finding_type>/<int:finding_id>/task', methods=['POST'])
@login_required
def update_finding_task(finding_type, finding_id):
    assigned_to = request.form.get('assigned_to', '').strip()
    status = request.form.get('status', 'Open')
    redirect_url = request.form.get('redirect_url', '')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if task already exists
    cursor.execute(
        'SELECT id FROM tasks WHERE finding_id = ? AND finding_type = ?',
        (finding_id, finding_type)
    )
    task = cursor.fetchone()
    
    if task:
        cursor.execute(
            'UPDATE tasks SET assigned_to = ?, status = ? WHERE id = ?',
            (assigned_to, status, task['id'])
        )
    else:
        cursor.execute(
            'INSERT INTO tasks (finding_id, finding_type, assigned_to, status) VALUES (?, ?, ?, ?)',
            (finding_id, finding_type, assigned_to, status)
        )
        
    conn.commit()
    conn.close()
    
    flash('Remediation task updated.', 'success')
    return redirect(redirect_url or url_for('dashboard'))

from flask import g

def api_key_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('X-API-KEY')
        if not api_key:
            return jsonify({'error': 'Unauthorized: Missing X-API-KEY header'}), 401
            
        # Hash key
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT user_id FROM api_keys WHERE key_value = ?', (key_hash,))
        key_record = cursor.fetchone()
        conn.close()
        
        if not key_record:
            return jsonify({'error': 'Unauthorized: Invalid API Key'}), 401
            
        g.api_user_id = key_record['user_id']
        return f(*args, **kwargs)
    return decorated

@app.route('/api/v1/scans')
@api_key_required
def api_v1_scans():
    user_id = g.api_user_id
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id, target_url, status, score, created_at FROM scans WHERE user_id = ? ORDER BY created_at DESC', (user_id,))
    scans = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(scans)

@app.route('/api/v1/report/<int:scan_id>')
@api_key_required
def api_v1_report(scan_id):
    user_id = g.api_user_id
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM scans WHERE id = ? AND user_id = ?', (scan_id, user_id))
    scan = cursor.fetchone()
    if not scan:
        conn.close()
        return jsonify({'error': 'Scan not found or unauthorized'}), 404
        
    cursor.execute('SELECT id, category, title, description, severity, remediation FROM scan_issues WHERE scan_id = ?', (scan_id,))
    issues = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify({
        'scan': dict(scan),
        'issues': issues
    })

@app.route('/api/v1/assets')
@api_key_required
def api_v1_assets():
    user_id = g.api_user_id
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id, name, type, tags, created_at FROM assets WHERE user_id = ? ORDER BY created_at DESC', (user_id,))
    assets = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(assets)

# Initialize database on startup
init_db()

if __name__ == '__main__':
    # Start local webserver on port 5000
    app.run(host='127.0.0.1', port=5000, debug=True)
