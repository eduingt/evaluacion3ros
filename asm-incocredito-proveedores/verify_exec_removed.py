with open('salida_test/b6_test.html', 'rb') as f:
    content = f.read()
# Check if exec-summary is removed
idx = content.find(b'exec-summary')
if idx >= 0:
    print('exec-summary STILL FOUND at:', idx)
    print(repr(content[max(0,idx-100):idx+200]))
else:
    print('exec-summary REMOVED')

# Check for the specific text
idx2 = content.find(b'Estado general (Puntuaci')
if idx2 >= 0:
    print('Text STILL FOUND at:', idx2)
else:
    print('Text REMOVED')

# Check section 3 still has KPI cards and gauges
idx3 = content.find(b'id="sec-tablero"')
if idx3 >= 0:
    print(repr(content[idx3:idx3+2000]))