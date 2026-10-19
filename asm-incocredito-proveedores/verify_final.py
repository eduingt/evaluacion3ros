with open('salida_test/b6_test.html', 'rb') as f:
    content = f.read()
# Check for Resumen de Seguridad
idx = content.find(b'Resumen de Seguridad')
print(f'Resumen de Seguridad: byte {idx}')
# Check Factores de Riesgo
idx2 = content.find(b'Factores de Riesgo de Overall Score')
print(f'Factores de Riesgo: byte {idx2}')
# Check page break before Factores
if idx2 >= 0:
    has_pb = b'page-break-before:always' in content[max(0,idx2-500):idx2]
    print(f'Page break before Factores: {has_pb}')
# Check page break before Resumen
if idx >= 0:
    has_pb = b'page-break-before:always' in content[max(0,idx-500):idx]
    print(f'Page break before Resumen: {has_pb}')
# Check order
if idx >= 0 and idx2 >= 0:
    print(f'Order correct (Resumen before Factores): {idx < idx2}')