import ast, sys
with open('app.py') as f:
    src = f.read()
try:
    ast.parse(src)
    print('app.py: syntax OK')
except SyntaxError as e:
    print(f'SyntaxError at line {e.lineno}: {e.msg}')
    sys.exit(1)
