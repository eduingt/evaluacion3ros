with open('salida_test/b6_test.html', 'rb') as f:
    content = f.read()
import re
sections = re.findall(b'id="sec-([^"]+)"', content)
for s in sections:
    print(s.decode())