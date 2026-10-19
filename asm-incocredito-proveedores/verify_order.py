with open('salida_test/b6_test.html', 'rb') as f:
    content = f.read()
# Check Resumen de Seguridad
idx = content.find(b'Resumen de Seguridad')
# Check Historial
idx2 = content.find(b'Historial del Score en los ultimos 30 dias')
print(f'Resumen at: {idx}')
print(f'Historial at: {idx2}')
print(f'Order correct (Resumen before Historial): {idx < idx2}')
print(f'Page break before Historial: {b"page-break-before:always" in content[max(0,idx2-100):idx2]}')