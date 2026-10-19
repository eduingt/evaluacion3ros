with open('salida_test/b6_test.html', 'rb') as f:
    content = f.read()
# Final comprehensive check
sections = [
    (b'Resumen de Seguridad', '1. RESUMEN DE SEGURIDAD'),
    (b'Factores de Riesgo de Overall Score', '2. Factores de Riesgo'),
    (b'Historial del Score en los ultimos 30 dias', '3. Historial del Score'),
    (b'5. Puntuaci\xc3\xb3n Global \xe2\x80\x94 Desglose Auditable', '4. Puntuación Global (4.1)'),
    (b'6. Elementos de acci\xc3\xb3n B7', '5. Elementos de acción (4.2)'),
]
print('Section 4 items:')
for marker, label in sections:
    idx = content.find(marker)
    has_pb = b'page-break-before:always' in content[max(0,idx-500):idx] if idx >= 0 else False
    print(f'  {label}: byte {idx} - Page break: {has_pb}')

# Factor modules (4.3.x)
print()
print('Factor modules (4.3.x):')
idx = content.find(b'<h3 class="mod">')
i = 1
while idx >= 0:
    has_pb = b'page-break-before:always' in content[max(0,idx-50):idx]
    end = content.find(b'</h3>', idx)
    name = content[idx+16:end].decode('utf-8', errors='ignore') if end >= 0 else 'unknown'
    print(f'  6.{i} {name}: Page break: {has_pb}')
    idx = content.find(b'<h3 class="mod">', idx + 1)
    i += 1