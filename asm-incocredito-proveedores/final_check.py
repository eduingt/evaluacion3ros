with open('salida_test/b6_test.html', 'rb') as f:
    content = f.read()
checks = [
    ('TOC 4: Overall Score', content.count(b'<span class="toc-num">4</span><a class="toc-title" href="#sec-b7ov">') == 1),
    ('TOC 4.1: Puntuación Global', content.count(b'<span class="toc-num">4.1</span><a class="toc-title" href="#sec-b7audit">') == 1),
    ('TOC 4.2: Elementos de acción', content.count(b'<span class="toc-num">4.2</span><a class="toc-title" href="#sec-b7accion">') == 1),
    ('TOC 4.3: Detalle por factor', content.count(b'<span class="toc-num">4.3</span><a class="toc-title" href="#sec-b7mod-appsec">') == 1),
    ('TOC 4.3.1-4.3.10: Factor modules', content.count(b'<span class="toc-num">4.3.') >= 10),
    ('Header 4.1 present', content.count(b'4.1 Puntuaci\xc3\xb3n Global') >= 1),
    ('Header 4.2 present', content.count(b'4.2 Elementos de acci\xc3\xb3n') >= 1),
    ('Old 5. header removed', content.count(b'5. Puntuaci\xc3\xb3n Global') == 0),
    ('Old 6. header removed', content.count(b'6. Elementos de acci\xc3\xb3n') == 0),
    ('Factor modules in body', content.count(b'sec-b7mod-') >= 10),
]
print('Final verification:')
for name, result in checks:
    status = 'PASS' if result else 'FAIL'
    print(f'  {status}: {name}')