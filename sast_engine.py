import ast
import re

class SastVisitor(ast.NodeVisitor):
    def __init__(self, source_lines):
        self.source_lines = source_lines
        self.findings = []

    def get_line_code(self, lineno):
        if lineno and 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    def visit_Call(self, node):
        # 1. Unsafe functions checking: eval and exec
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name in ('eval', 'exec'):
                self.findings.append({
                    'line_number': node.lineno,
                    'category': 'RCE Risk',
                    'title': f'Unsafe Function Call: {func_name}()',
                    'description': f'Usage of {func_name}() can lead to Remote Code Execution (RCE) if evaluated input is untrusted.',
                    'severity': 'high',
                    'remediation': f'Replace {func_name}() with safer structural parsing APIs (e.g., ast.literal_eval() or json.loads()).',
                    'code_line': self.get_line_code(node.lineno)
                })
                
        # 2. Command Injection risks: subprocess or os.system calls
        elif isinstance(node.func, ast.Attribute):
            # Checking calls like os.system()
            if isinstance(node.func.value, ast.Name) and node.func.value.id == 'os' and node.func.attr == 'system':
                self.findings.append({
                    'line_number': node.lineno,
                    'category': 'Command Injection',
                    'title': 'Unsafe OS Shell Execution',
                    'description': 'os.system() bypasses shell abstraction and is prone to shell injection command vulnerabilities.',
                    'severity': 'high',
                    'remediation': 'Use the subprocess module with specific argument arrays (shell=False) instead.',
                    'code_line': self.get_line_code(node.lineno)
                })
            
            # Checking subprocess.call or Popen where shell=True
            elif isinstance(node.func.value, ast.Name) and node.func.value.id == 'subprocess':
                # Check keyword arguments for shell=True
                shell_true = False
                for kw in node.keywords:
                    if kw.arg == 'shell' and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        shell_true = True
                
                if shell_true:
                    self.findings.append({
                        'line_number': node.lineno,
                        'category': 'Command Injection',
                        'title': 'Subprocess Spawned with shell=True',
                        'description': 'Spawning a subprocess through the system shell (shell=True) invites arbitrary shell string execution exploits.',
                        'severity': 'medium',
                        'remediation': 'Change keyword shell=False and pass the command parameters as a list of strings.',
                        'code_line': self.get_line_code(node.lineno)
                    })
                    
            # 3. SQL Injection checks in sqlite3 or db calls
            elif node.func.attr in ('execute', 'executemany'):
                # Check if the first positional argument is an f-string or string addition
                if node.args:
                    first_arg = node.args[0]
                    is_unsafe = False
                    
                    if isinstance(first_arg, ast.JoinedStr): # f-string e.g. f"SELECT * FROM x WHERE id={id}"
                        is_unsafe = True
                    elif isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Add): # e.g. "SELECT..." + id
                        is_unsafe = True
                    
                    if is_unsafe:
                        self.findings.append({
                            'line_number': node.lineno,
                            'category': 'SQL Injection',
                            'title': 'Unsafe SQL Parameter Formatting',
                            'description': 'Dynamic string building inside execution query strings permits SQL Injection exploits.',
                            'severity': 'high',
                            'remediation': 'Use parameterized SQL syntax (e.g., execute("SELECT * FROM users WHERE name = ?", (name,))) instead of string formatting.',
                            'code_line': self.get_line_code(node.lineno)
                        })

        self.generic_visit(node)

    def visit_Assign(self, node):
        # 4. Hardcoded API secrets and credentials
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                # Check if var name matches credentials keywords
                if any(kw in var_name for kw in ('password', 'secret', 'api_key', 'token', 'private_key')):
                    # Check if value is a static string literal and not empty
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        secret_val = node.value.value.strip()
                        if secret_val and len(secret_val) > 4:
                            self.findings.append({
                                'line_number': node.lineno,
                                'category': 'Credential Leak',
                                'title': f'Hardcoded Secrets Discovered: {target.id}',
                                'description': f'A plain-text string literal is assigned to credentials variable: "{target.id}".',
                                'severity': 'high',
                                'remediation': 'Move sensitive authentication secrets out of the codebase and load them from environment variables.',
                                'code_line': self.get_line_code(node.lineno)
                            })
        self.generic_visit(node)

def analyze_code(source_code):
    findings = []
    source_lines = source_code.splitlines()
    
    # Check Syntax Validity first
    try:
        tree = ast.parse(source_code)
    except SyntaxError as e:
        # Compile error finding
        return [{
            'line_number': e.lineno or 1,
            'category': 'Syntax Error',
            'title': 'Python Syntax Failure',
            'description': f'Failed compile: {e.msg}',
            'severity': 'high',
            'remediation': 'Fix syntax mismatch formatting (e.g. brackets, tabs/spaces indentations).',
            'code_line': source_lines[e.lineno - 1].strip() if e.lineno and e.lineno <= len(source_lines) else ""
        }], 0
        
    # Walk tree using visitor class
    visitor = SastVisitor(source_lines)
    visitor.visit(tree)
    findings = visitor.findings
    
    # Hardcoded regex checks for inline credentials that might escape AST assignment
    # e.g., in dictionaries or lists
    for idx, line in enumerate(source_lines):
        lineno = idx + 1
        # Match pattern: password = '...' or secret_key = '...'
        # Excluding comment lines
        if line.strip().startswith('#'):
            continue
            
        pattern = r'(?i)\b(password|secret|api_key|token|private_key)\b\s*[:=]\s*[\'"]([^\'"]{5,})[\'"]'
        matches = re.findall(pattern, line)
        for match in matches:
            # Check if this finding is already captured for the same line
            already_captured = any(f['line_number'] == lineno and 'Secrets' in f['title'] for f in findings)
            if not already_captured:
                findings.append({
                    'line_number': lineno,
                    'category': 'Credential Leak',
                    'title': f'Inline secret leak: {match[0]}',
                    'description': f'Hardcoded credential value for "{match[0]}" detected in plain text.',
                    'severity': 'high',
                    'remediation': 'Load values from environment variables or key vaults instead of committing credentials.',
                    'code_line': line.strip()
                })

    # Scoring calculations
    score = 100
    for f in findings:
        if f['severity'] == 'high':
            score -= 20
        elif f['severity'] == 'medium':
            score -= 10
        elif f['severity'] == 'low':
            score -= 5
            
    score = max(0, min(100, score))
    return findings, score
