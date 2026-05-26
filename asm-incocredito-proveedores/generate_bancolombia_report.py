#!/usr/bin/env python3
"""
Genera informe PDF ver.bancolombia con identidad grafica de Bancolombia.
Basado en generate_socradar_style_report.py pero con branding propio.
"""

from __future__ import annotations

import argparse
import html
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent

LOGO_B64 = "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjE3IiBoZWlnaHQ9IjYxIiB2aWV3Qm94PSIwIDAgMjE3IDYxIiBmaWxsPSJub25lIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPgo8cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTI1Ljg3NTYgMjYuODM4NEMyNi4wMDEzIDI3LjMyNTcgMjYuNDkxNiAyNy41NzcgMjYuOTg5NyAyNy40MTE4QzMxLjA3MzUgMjYuMTU3NSAzNS4xNjc0IDI1LjI5OTEgMzkuMzkxNCAyNC42NzQ3QzM5Ljg3NTUgMjQuNjEgNDAuMTQwNCAyNC4xMTAzIDM5Ljk2MjQgMjMuNjA5MUMzOS41ODc0IDIyLjU1MjkgMzkuMzk3OCAyMi4wMjYyIDM5LjAxNDUgMjAuOTc2MkMzOC44NTE4IDIwLjUzMDMgMzguNDExNiAyMC4yMzc5IDM3Ljk2MTEgMjAuMjg2N0MzMy44MzMgMjAuNzk0NyAyOS44NDQ3IDIxLjU0NSAyNS44NDc3IDIyLjcwMDdDMjUuMzI3MiAyMi44NjM4IDI1LjAwNzYgMjMuNDQ1NiAyNS4xMzg4IDIzLjk2MTdDMjUuNDMwOSAyNS4xMTA3IDI1LjU3ODMgMjUuNjg1OSAyNS44NzU2IDI2LjgzODRaIiBmaWxsPSIjRkQwRDFCIi8+CjxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNNDIuNDMwNSAyNy40MTU3QzQyLjI3MiAyNi45NDM3IDQxLjg0MTggMjYuNjI4MiA0MS40MTY0IDI2LjY4MzhDMzQuOTUzOCAyNy41MDYxIDI4LjY2MDkgMjkuMTAwOCAyMi42OTM2IDMxLjczNjRDMjIuMjU4MyAzMS45NDE5IDIxLjk5NzIgMzIuNDg4NCAyMi4wODg0IDMyLjk3QzIyLjMyMjQgMzQuMjAxOCAyMi40NDA0IDM0LjgxODMgMjIuNjc5MiAzNi4wNTI0QzIyLjc4MTIgMzYuNTgwMSAyMy4yNzUgMzYuODIzMSAyMy43NjIgMzYuNTg2MUMyOS44MjM0IDMzLjgxNTEgMzYuMjI4OCAzMi4wNTA4IDQyLjc5OTkgMzAuOTk4OEM0My4yMTc1IDMwLjkzMDUgNDMuNDMwNSAzMC40NTI4IDQzLjI3MDcgMjkuOTYwNkM0Mi45Mzk3IDI4Ljk0MDEgNDIuNzcxNSAyOC40MzEyIDQyLjQzMDUgMjcuNDE1N1oiIGZpbGw9IiNGRDBEMUIiLz4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik00Mi40MDk1IDM0LjI5NDVDNDIuMjQ5MyAzMy43OTA3IDQxLjc4MTIgMzMuNDYyIDQxLjMzNjQgMzMuNTUzM0MzNy4zMDEyIDM0LjQyNzIgMzMuMzU3IDM1LjQ4MDQgMjkuNDQ5NyAzNi44MjA1QzI4Ljk1NDIgMzcuMDAyMSAyOC42NzUxIDM3LjUyMzkgMjguODA1MyAzOC4wMDM5QzI5LjExNTkgMzkuMTQ3NSAyOS4yNzIzIDM5LjcyMDIgMjkuNTg2NyA0MC44Njc0QzI5LjczNDQgNDEuNDA2MyAzMC4zNDA0IDQxLjY4MiAzMC44OTg2IDQxLjQ2OTdDMzQuODA0NCA0MC4wNzM1IDM4Ljc0OTUgMzguODU0NCA0Mi43ODA5IDM3Ljg3N0M0My4xNjc1IDM3Ljc4MzIgNDMuMzU3OCAzNy4zMzA2IDQzLjIxNDEgMzYuODYzN0M0Mi44OTY3IDM1LjgzMzggNDIuNzM1OSAzNS4zMTk5IDQyLjQwOTUgMzQuMjk0NVoiIGZpbGw9IiNGRDBEMUIiLz4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik01Ny44MTg2IDMzLjE2NjRDNTcuODE4NiAzMS43ODA4IDU2LjkzNTYgMzEuMjA1NyA1NS4xOTU1IDMxLjIwNTdINTMuMTE3OVYzNS4xMjY5SDU1LjE2OTZDNTYuODU3NyAzNS4xMjY5IDU3LjgxODYgMzQuNDQ3NCA1Ny44MTg2IDMzLjE2NjRaTTU0Ljc4IDI0LjMzMDRDNTQuMjM0NiAyNC4zMzA0IDUzLjY2MzQgMjQuMzgyNyA1My4xMTc5IDI0LjQ2MTJWMjcuOTM4SDU0Ljg4MzlDNTYuNDQyIDI3LjkzOCA1Ny4xNjkzIDI3LjI4NDQgNTcuMTY5MyAyNi4xNjA0QzU3LjE2OTMgMjUuMDg4NiA1Ni40MTYyIDI0LjMzMDQgNTQuNzggMjQuMzMwNFpNNjIuMDc3NCAzMy4zNDk0QzYyLjA3NzQgMzYuNDA3OSA1OS4wMTMxIDM4LjQ0NzEgNTUuNTMzIDM4LjQ0NzFINDkuMTQ0NVYyMS41NTk1QzUxLjI3NDEgMjEuMjQ1OCA1Mi44ODQzIDIxLjAzNjYgNTQuNzggMjEuMDM2NkM1OC4yODU5IDIxLjAzNjYgNjEuMDkwNyAyMi42ODM0IDYxLjA5MDcgMjUuNTU5MkM2MS4wOTA3IDI3LjIwNiA2MC4yMzM3IDI4LjMwNCA1OC43MDE0IDI4LjkwNTNDNjEuMDY0OCAyOS41ODUgNjIuMDc3NCAzMS4wMjI4IDYyLjA3NzQgMzMuMzQ5NFoiIGZpbGw9IiNGRDBEMUIiLz4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik03MS4yMjY4IDM1LjEwMVYzMi44NTI4SDcwLjQ3MzZDNjguNzA3OCAzMi44NTI4IDY3LjA5NzYgMzMuMjQ1IDY3LjA5NzYgMzQuNDczNUM2Ny4wOTc2IDM1LjQxNDcgNjcuNzIwOSAzNS43NTQ1IDY4Ljk5MzUgMzUuNzU0NUM3MC4wMDYzIDM1Ljc1NDUgNzAuODM3MiAzNS40NDA2IDcxLjIyNjggMzUuMTAxWk03NS4wNDQzIDMwLjIxMjRWMzcuMDg3NkM3My42NDIxIDM4LjE1OTUgNzEuMzgyNiAzOC43MzQ2IDY4LjMxODIgMzguNzM0NkM2NS41OTE1IDM4LjczNDYgNjMuMzMyIDM3LjYxMDUgNjMuMzMyIDM1LjEyNjlDNjMuMzMyIDMxLjM4ODcgNjYuOTQxOCAzMC40NzM4IDcxLjIyNjggMzAuMzQzMUM3MS4xNDg5IDI4LjcyMjMgNzAuNDk5NiAyOC4zMDQgNjkuMDcxMiAyOC4zMDRDNjguMzE4MiAyOC4zMDQgNjYuMzE4NSAyOC42NDM4IDY2LjA1OSAyOC42NDM4QzY1LjQzNTUgMjguNjQzOCA2NC45NDIyIDI4LjI1MTcgNjQuNTI2NyAyNy4xMDE2TDY0LjIxNDkgMjYuMTYwNEM2NS44MjUgMjUuNTU5MiA2Ny40MDkzIDI1LjE0MDkgNjkuMTIzMyAyNS4xNDA5QzcyLjg2MjkgMjUuMTQwOSA3NS4wNDQzIDI2LjU1MjYgNzUuMDQ0MyAzMC4yMTI0WiIgZmlsbD0iI0ZEMEQxQiIvPgo8cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTg5LjM0MjkgMjkuMTQwNlYzOC40NDcxSDg1LjQ0NzVWMzAuNTI2Qzg1LjQ0NzUgMjkuMTQwNiA4NC41Mzg3IDI4LjQzNDcgODIuOTU0NSAyOC40MzQ3QzgyLjM1NzMgMjguNDM0NyA4MS43ODU5IDI4LjUxMzEgODEuMjkyMyAyOC42NDM5VjM4LjQ0NzFINzcuMzcxMUw3Ny4zOTY5IDI2LjgxNEM3OS4wMzMgMjUuNzE2IDgxLjY4MTkgMjUuMTE0NyA4My44Mzc1IDI1LjExNDdDODYuODI0MSAyNS4xMTQ3IDg5LjM0MjkgMjYuNjA0NyA4OS4zNDI5IDI5LjE0MDZaIiBmaWxsPSIjRkQwRDFCIi8+CjxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNOTEuMDM1MiAzMi4wNjg2QzkxLjAzNTIgMjcuNDkzNiA5NC4yMDM0IDI1LjA4ODYgOTguMzA2NiAyNS4wODg2Qzk5LjQ0OTMgMjUuMDg4NiAxMDAuNDg4IDI1LjI0NTUgMTAxLjczNSAyNS41MzMxQzEwMS41NzkgMjYuODQwMiAxMDEuMDMzIDI3Ljk5MDMgMTAwLjQzNiAyOC42NDM5Qzk5Ljk5NDcgMjguNTEzMiA5OS4yNjc1IDI4LjQwODYgOTguODUyMiAyOC40MDg2Qzk2LjIyOTEgMjguNDA4NiA5NS4xNjQzIDI5Ljc2OCA5NS4xNjQzIDMxLjgzMzNDOTUuMTY0MyAzMy45MjQ2IDk2LjE1MTIgMzUuMjA1NiA5OC42MTgzIDM1LjIwNTZDOTkuMjkzNyAzNS4yMDU2IDEwMC4wNzMgMzUuMDc0OCAxMDEuMDMzIDM0LjczNDhMMTAxLjczNSAzNy44NzJDMTAwLjMwNiAzOC40NDcxIDk4LjgyNiAzOC43MDg1IDk3LjY1NzQgMzguNzA4NUM5My42NTgyIDM4LjcwODUgOTEuMDM1MiAzNi4zMDM0IDkxLjAzNTIgMzIuMDY4NloiIGZpbGw9IiNGRDBEMUIiLz4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik0xMTIuMTIzIDMxLjg4NTZDMTEyLjEyMyAyOS43NDE5IDExMS4wODQgMjguNDg3IDEwOS4yNjYgMjguNDg3QzEwNy41IDI4LjQ4NyAxMDYuNDEgMjkuNzQxOSAxMDYuNDEgMzEuODg1NkMxMDYuNDEgMzQuMTMzNyAxMDcuNDc1IDM1LjMxMDEgMTA5LjI2NiAzNS4zMTAxQzExMS4wODQgMzUuMzEwMSAxMTIuMTIzIDM0LjEzMzcgMTEyLjEyMyAzMS44ODU2Wk0xMDIuNDg4IDMxLjg4NTZDMTAyLjQ4OCAyNy43MDI3IDEwNS4yOTMgMjUuMDg4NiAxMDkuMjY2IDI1LjA4ODZDMTEzLjM5NSAyNS4wODg2IDExNi4wNDQgMjcuODA3MyAxMTYuMDQ0IDMxLjg4NTZDMTE2LjA0NCAzNi4wOTQyIDExMy4zNyAzOC43MDg1IDEwOS4yNjYgMzguNzA4NUMxMDUuMTM3IDM4LjcwODUgMTAyLjQ4OCAzNi4wMTYgMTAyLjQ4OCAzMS44ODU2WiIgZmlsbD0iI0ZEMEQxQiIvPgo8cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTExOC4yNSAyMS42NjRDMTE5LjE1OSAyMC45ODQzIDEyMS4xMzMgMjAuNDA5MiAxMjIuMTcxIDIwLjQwOTJWMzguNDQ3SDExOC4yNVYyMS42NjRaIiBmaWxsPSIjRkQwRDFCIi8+CjxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNMTM0LjAxNCAzMS44ODU2QzEzNC4wMTQgMjkuNzQxOSAxMzIuOTc1IDI4LjQ4NyAxMzEuMTU3IDI4LjQ4N0MxMjkuMzkxIDI4LjQ4NyAxMjguMyAyOS43NDE5IDEyOC4zIDMxLjg4NTZDMTI4LjMgMzQuMTMzNyAxMjkuMzY1IDM1LjMxMDEgMTMxLjE1NyAzNS4zMTAxQzEzMi45NzUgMzUuMzEwMSAxMzQuMDE0IDM0LjEzMzcgMTM0LjAxNCAzMS44ODU2Wk0xMjQuMzc5IDMxLjg4NTZDMTI0LjM3OSAyNy43MDI3IDEyNy4xODQgMjUuMDg4NiAxMzEuMTU3IDI1LjA4ODZDMTM1LjI4NiAyNS4wODg2IDEzNy45MzUgMjcuODA3MyAxMzcuOTM1IDMxLjg4NTZDMTM3LjkzNSAzNi4wOTQyIDEzNS4yNiAzOC43MDg1IDEzMS4xNTcgMzguNzA4NUMxMjcuMDI4IDM4LjcwODUgMTI0LjM3OSAzNi4wMTYgMTI0LjM3OSAzMS44ODU2WiIgZmlsbD0iI0ZEMEQxQiIvPgo8cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTE1OS43NzYgMjkuMTQwNlYzOC40NDcxSDE1NS45MDZWMzAuNTI2QzE1NS45MDYgMjkuMTQwNiAxNTUuMDIzIDI4LjQzNDcgMTUzLjQ2NSAyOC40MzQ3QzE1Mi43MzggMjguNDM0NyAxNTIuMDM3IDI4LjU5MTYgMTUxLjQ2NSAyOC44MjY5QzE1MS42NzMgMjkuNDAyIDE1MS43NzcgMzAuMDI5NCAxNTEuNzc3IDMwLjcwOTFWMzguNDQ3MUgxNDcuOTA3VjMwLjUyNkMxNDcuOTA3IDI5LjE0MDYgMTQ3LjAyNCAyOC40MzQ3IDE0NS40NjYgMjguNDM0N0MxNDQuODY5IDI4LjQzNDcgMTQ0LjI5OCAyOC41MTMxIDE0My44MDQgMjguNjQzOVYzOC40NDcxSDEzOS44ODNMMTM5LjkwOSAyNi44MTRDMTQxLjQ2NyAyNS43MTYgMTQzLjkwOCAyNS4xMTQ3IDE0NS45NiAyNS4xMTQ3QzE0Ny41OTYgMjUuMTE0NyAxNDguOTk4IDI1LjY2MzcgMTUwLjAxMSAyNi41NTI2QzE1MS4zMzUgMjUuNjg5NyAxNTMuMTc5IDI1LjExNDcgMTU0LjczNyAyNS4xMTQ3QzE1Ny41NjggMjUuMTE0NyAxNTkuNzc2IDI2LjYzMDkgMTU5Ljc3NiAyOS4xNDA2WiIgZmlsbD0iI0ZEMEQxQiIvPgo8cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTE3MS42NDcgMzEuNzAyNUMxNzEuNjQ3IDI5LjI5NzQgMTcwLjQgMjguNDM0NyAxNjguNCAyOC40MzQ3QzE2Ny41OTUgMjguNDM0NyAxNjYuOTQ2IDI4LjU5MTUgMTY2LjM3NSAyOC44NTNWMzUuNDE0N0MxNjcuMDc2IDM1LjUxOTEgMTY3Ljc1MSAzNS41NzEzIDE2OC4zNzQgMzUuNTcxM0MxNzAuNjYgMzUuNTcxMyAxNzEuNjQ3IDMzLjc5MzggMTcxLjY0NyAzMS43MDI1Wk0xNzUuNTE2IDMxLjIwNTdDMTc1LjUxNiAzNS45NjM1IDE3Mi43MTEgMzguNzA4NSAxNjguMTQxIDM4LjcwODVDMTY1LjkwNyAzOC43MDg1IDE2My43NTIgMzguMjkwMiAxNjIuNDUzIDM3LjY4OTFWMjEuNjY0QzE2My4zNjIgMjAuOTg0MyAxNjUuMzYyIDIwLjQwOTIgMTY2LjM3NSAyMC40MDkyVjI2LjYwNDdDMTY3LjQ5MSAyNS42Mzc2IDE2OC44NDIgMjUuMTE0NyAxNzAuMDYyIDI1LjExNDdDMTczLjkzMiAyNS4xMTQ3IDE3NS41MTYgMjcuODA3MyAxNzUuNTE2IDMxLjIwNTdaIiBmaWxsPSIjRkQwRDFCIi8+CjxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNMTc3LjcyNCAyNS40ODA3QzE3OC4yNjkgMjUuMjQ1NSAxNzguOTQ1IDI1LjExNDcgMTc5LjY5OCAyNS4xMTQ3QzE4MC40NTEgMjUuMTE0NyAxODEuMSAyNS4yNDU1IDE4MS42NDUgMjUuNDgwN1YzOC40NDcxSDE3Ny43MjRWMjUuNDgwN1pNMTc3LjY3MiAyMS4zNTAyQzE3Ny42NzIgMjAuMjUyMyAxNzguNTgxIDE5LjMzNzMgMTc5LjY3MiAxOS4zMzczQzE4MC43ODggMTkuMzM3MyAxODEuNjk3IDIwLjIyNjIgMTgxLjY5NyAyMS4zNTAyQzE4MS42OTcgMjIuNDIyIDE4MC43ODggMjMuMzYzMiAxNzkuNjcyIDIzLjM2MzJDMTc4LjU4MSAyMy4zNjMyIDE3Ny42NzIgMjIuNDc0MyAxNzcuNjcyIDIxLjM1MDJaIiBmaWxsPSIjRkQwRDFCIi8+CjxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNMTkxLjQ4OSAzNS4xMDFWMzIuODUyOEgxOTAuNzM2QzE4OC45NyAzMi44NTI4IDE4Ny4zNTkgMzMuMjQ1IDE4Ny4zNTkgMzQuNDczNUMxODcuMzU5IDM1LjQxNDcgMTg3Ljk4MyAzNS43NTQ1IDE4OS4yNTUgMzUuNzU0NUMxOTAuMjY4IDM1Ljc1NDUgMTkxLjA5OSAzNS40NDA2IDE5MS40ODkgMzUuMTAxWk0xOTUuMzA3IDMwLjIxMjRWMzcuMDg3NkMxOTMuOTA0IDM4LjE1OTUgMTkxLjY0NSAzOC43MzQ2IDE4OC41OCAzOC43MzQ2QzE4NS44NTMgMzguNzM0NiAxODMuNTk0IDM3LjYxMDUgMTgzLjU5NCAzNS4xMjY5QzE4My41OTQgMzEuMzg4NyAxODcuMjA0IDMwLjQ3MzggMTkxLjQ4OSAzMC4zNDMxQzE5MS40MTEgMjguNzIyMyAxOTAuNzYyIDI4LjMwNCAxODkuMzMzIDI4LjMwNEMxODguNTggMjguMzA0IDE4Ni41OCAyOC42NDM4IDE4Ni4zMjEgMjguNjQzOEMxODUuNjk3IDI4LjY0MzggMTg1LjIwNCAyOC4yNTE3IDE4NC43ODggMjcuMTAxNkwxODQuNDc3IDI2LjE2MDRDMTg2LjA4NyAyNS41NTkyIDE4Ny42NzEgMjUuMTQwOSAxODkuMzg1IDI1LjE0MDlDMTkzLjEyNSAyNS4xNDA5IDE5NS4zMDcgMjYuNTUyNiAxOTUuMzA3IDMwLjIxMjRaIiBmaWxsPSIjRkQwRDFCIi8+Cjwvc3ZnPgo="


def esc(s: Any) -> str:
    return html.escape(str(s if s is not None else ""), quote=True)


def parse_matrix_row(m: dict[str, Any]) -> dict[str, Any]:
    spf_dmarc = str(m.get("spf_dmarc", ""))
    spf_ok = "SPF:ok" in spf_dmarc
    spf_missing = "SPF:missing" in spf_dmarc
    spf_partial = "SPF:partial" in spf_dmarc
    dm = re.search(r"DMARC:(\S+)", spf_dmarc)
    dmarc = dm.group(1) if dm else "-"
    https = m.get("https")
    https_ok = isinstance(https, int) and 200 <= https < 400
    mx_records = m.get("mx_records", [])
    ns_records = m.get("ns_records", [])
    dns = m.get("dns") or {}
    dkim_records = dns.get("dkim_records", [])
    dane_records = dns.get("dane_records", [])
    ip_reputation = dns.get("ip_reputation", [])
    starttls_results = dns.get("starttls_results") or []
    return {
        **m,
        "https_ok": https_ok,
        "spf_ok": spf_ok,
        "spf_missing": spf_missing,
        "spf_partial": spf_partial,
        "dmarc_label": dmarc,
        "mx_count": len(mx_records),
        "ns_count": len(ns_records),
        "dnssec_ok": bool(dns.get("dnssec_ok")),
        "dkim_count": len(dkim_records),
        "dane_count": len(dane_records),
        "ip_reputation_count": len(ip_reputation),
        "ip_reputation_clean": len(ip_reputation) == 0,
        "supply_chain_count": m.get("supply_chain_count", 0),
        "starttls_ok": all(s.get("starttls") for s in starttls_results) if starttls_results else False,
        "starttls_count": len(starttls_results),
        "csp_findings": m.get("csp_findings") or [],
        "csp_finding_count": len(m.get("csp_findings") or []),
        "cookie_findings": m.get("cookie_findings") or [],
        "cookie_insecure": any(f.get("severity") in ("high",) for f in (m.get("cookie_findings") or [])),
        "supply_reputation_dnsbl_count": m.get("supply_reputation_dnsbl_count", 0),
        "supply_reputation_urlhaus_count": m.get("supply_reputation_urlhaus_count", 0),
        "supply_reputation_clean": m.get("supply_reputation_clean", True),
    }


def domain_score(p: dict[str, Any]) -> float:
    pts = 0.0
    h = p.get("https", {}) or {}
    headers = h.get("headers") or {}
    tls = p.get("tls") or {}
    dns = p.get("dns") or {}
    if p.get("port_443", {}).get("open"):
        pts += 8
    if p.get("port_80", {}).get("open"):
        pts += 2
    if isinstance(h.get("status_code"), int) and 200 <= h["status_code"] < 400:
        pts += 18
    if headers.get("strict-transport-security"):
        pts += 12
    if headers.get("content-security-policy") or headers.get("content-security-policy-report-only"):
        pts += 10
    if headers.get("x-frame-options"):
        pts += 6
    if headers.get("x-content-type-options"):
        pts += 4
    if tls.get("negotiated_version") and not tls.get("error"):
        pts += 14
    if tls.get("tls13_only_ok"):
        pts += 6
    if dns.get("spf_record") and "-all" in str(dns["spf_record"]).replace(" ", "").lower():
        pts += 10
    elif dns.get("spf_record"):
        pts += 5
    if dns.get("dmarc_policy") in ("reject", "quarantine"):
        pts += 10
    elif dns.get("dmarc_policy"):
        pts += 5
    starttls = dns.get("starttls_results") or []
    if starttls and all(s.get("starttls") for s in starttls):
        pts += 5
    elif starttls:
        pts += 1
    ip_reputation = dns.get("ip_reputation") or []
    if not ip_reputation:
        pts += 8
    elif len(ip_reputation) <= 2:
        pts += 4
    urlhaus = p.get("urlhaus") or {}
    if not urlhaus.get("malicious"):
        pts += 5
    elif urlhaus.get("error"):
        pts += 1
    vulns = p.get("vulnerabilities") or []
    if not vulns:
        pts += 8
    elif len(vulns) <= 3:
        pts += 4
    leaks = p.get("credential_leaks") or []
    valid_leaks = [l for l in leaks if "error" not in l]
    if not valid_leaks:
        pts += 6
    elif len(valid_leaks) <= 2:
        pts += 3
    typos = p.get("typosquatting") or []
    if not typos:
        pts += 6
    elif len(typos) <= 2:
        pts += 3
    patch = p.get("patching") or []
    eol_count = sum(1 for x in patch if x.get("status") == "eol")
    if eol_count == 0:
        pts += 5
    elif eol_count <= 1:
        pts += 2
    supply = p.get("supply_chain") or []
    if not supply:
        pts += 4
    elif len(supply) <= 5:
        pts += 2
    takeover = p.get("takeover_risks") or []
    vulnerable = any(r.get("vulnerable") for r in takeover)
    if not takeover: pts += 6
    elif not vulnerable: pts += 3
    csp_f = p.get("csp_findings") or []
    if not csp_f: pts += 5
    elif all(f.get("severity") in ("low", "medium") for f in csp_f): pts += 2
    cookie_f = p.get("cookie_findings") or []
    cookie_insecure = any(f.get("severity") in ("high",) for f in cookie_f)
    if not cookie_f: pts += 5
    elif not cookie_insecure: pts += 2
    scr_dnsbl = p.get("supply_reputation_dnsbl_count", 0)
    scr_urlhaus = p.get("supply_reputation_urlhaus_count", 0)
    if scr_dnsbl == 0 and scr_urlhaus == 0: pts += 5
    elif scr_dnsbl <= 2 and scr_urlhaus == 0: pts += 2
    return min(100.0, round(pts, 2))


def build_report(asm: dict[str, Any], title: str, subtitle: str, version: str) -> str:
    providers = asm.get("providers") or []
    matrix = [parse_matrix_row(m) for m in (asm.get("matrix") or [])]
    gen = str(asm.get("generated_utc", ""))
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    n = len(providers)
    scores = [domain_score(p) for p in providers]
    trust = round(sum(scores) / max(1, n), 2)

    missing_hsts = sum(1 for m in matrix if not m.get("hsts"))
    missing_csp = sum(1 for m in matrix if not m.get("csp"))
    missing_headers = sum(1 for m in matrix if not m.get("hsts") or not m.get("csp"))
    spf_missing = sum(1 for m in matrix if m.get("spf_missing"))
    spf_partial = sum(1 for m in matrix if m.get("spf_partial"))
    https_fail = sum(1 for m in matrix if not m.get("https_ok"))
    tls_issues = sum(1 for m in matrix if not m.get("tls_version") and m.get("puertos", "").find("443:open") >= 0)

    total_subs = sum(len(p.get("subdomains") or []) for p in providers)
    total_crt = sum(len(p.get("crt_subdomains") or []) for p in providers)
    total_san = sum(len(p.get("san_list") or []) for p in providers)
    has_caa = sum(1 for p in providers if p.get("caa_records"))
    has_mta_sts = sum(1 for p in providers if p.get("mta_sts"))
    has_tls_rpt = sum(1 for p in providers if p.get("tls_rpt"))
    has_bimi = sum(1 for p in providers if p.get("bimi"))
    open443 = sum(1 for p in providers if (p.get("port_443") or {}).get("open"))
    open80 = sum(1 for p in providers if (p.get("port_80") or {}).get("open"))
    total_vulns = sum(len(p.get("vulnerabilities") or []) for p in providers)

    starttls_missing = sum(1 for m in matrix if not m.get("starttls_ok") and m.get("mx_count", 0) > 0)

    risk_rows = [
        ("Application Security", "HTTP Missing Security Headers (HSTS o CSP)", missing_headers, "Medium"),
        ("Email Security", "SPF ausente o dominio sin resolucion", spf_missing, "Medium"),
        ("Email Security", "SPF parcial / endurecimiento pendiente", spf_partial, "Low"),
        ("Email Security", "STARTTLS no soportado en MX", starttls_missing, "Medium"),
        ("SSL-TLS", "HTTPS no verificable o error TLS en apex", https_fail, "High"),
        ("SSL-TLS", "TLS negociado no constatado con 443 abierto", tls_issues, "Medium"),
    ]
    if total_vulns:
        risk_rows.insert(0, ("Vulnerability Management", f"CVEs detectados en tecnologias del servidor", total_vulns, "High"))
    total_leaks = sum(len([l for l in (p.get("credential_leaks") or []) if "error" not in l]) for p in providers)
    if total_leaks:
        risk_rows.insert(0, ("Credential Security", "Dominios en breaches de credenciales conocidos", total_leaks, "High"))
    total_typos = sum(len(p.get("typosquatting") or []) for p in providers)
    if total_typos:
        risk_rows.insert(0, ("Phishing", "Posibles dominios typosquatting resolviendo", total_typos, "High"))
    total_patch_eol = sum(sum(1 for x in (p.get("patching") or []) if x.get("status") == "eol") for p in providers)
    if total_patch_eol:
        risk_rows.insert(0, ("Software Maintenance", "Tecnologias EOL detectadas", total_patch_eol, "High"))
    total_takeover = sum(len(p.get("takeover_risks") or []) for p in providers)
    if total_takeover:
        risk_rows.insert(0, ("Subdomain Takeover", "Posibles subdominios vulnerables a takeover", total_takeover, "High"))
    total_csp_weak = sum(len(p.get("csp_findings") or []) for p in providers)
    if total_csp_weak:
        risk_rows.insert(0, ("Application Security", "Debilidades en CSP detectadas", total_csp_weak, "Medium"))
    total_cookie_insecure = sum(1 for p in providers if any(f.get("severity") in ("high",) for f in (p.get("cookie_findings") or [])))
    if total_cookie_insecure:
        risk_rows.insert(0, ("Application Security", "Cookies sin flags de seguridad (Secure/HttpOnly)", total_cookie_insecure, "Medium"))
    total_scr_dnsbl = sum(m.get("supply_reputation_dnsbl_count", 0) for m in matrix)
    total_scr_urlhaus = sum(m.get("supply_reputation_urlhaus_count", 0) for m in matrix)
    if total_scr_dnsbl or total_scr_urlhaus:
        risk_rows.insert(0, ("Supply Chain Reputation", "IPs o dominios de terceros con reputacion negativa (DNSBL/URLhaus)", total_scr_dnsbl + total_scr_urlhaus, "High"))
    total_supply = sum(len(p.get("supply_chain") or []) for p in providers)
    if total_supply:
        risk_rows.insert(0, ("Supply Chain", "Dependencias de terceros detectadas (CSP/scripts)", total_supply, "Low"))

    def risk_table_rows() -> str:
        out = []
        for cat, name, cnt, severity in risk_rows:
            if cnt <= 0:
                continue
            badge = {"High": "high", "Medium": "med", "Low": "low"}.get(severity, "low")
            out.append(
                f'<tr><td>{esc(cat)}</td><td>{esc(name)}</td>'
                f'<td class="num">{cnt}</td><td><span class="sev {badge}">{severity}</span></td></tr>'
            )
        if not out:
            out.append("<tr><td colspan='4' class='muted'>Sin hallazgos en las categorias mostradas.</td></tr>")
        return "\n".join(out)

    def grade_from_trust(t: float) -> str:
        if t >= 90: return "A"
        if t >= 75: return "B"
        if t >= 60: return "C"
        if t >= 45: return "D"
        if t >= 30: return "E"
        return "F"

    grade = grade_from_trust(trust)

    def vuln_block(esc_f, vulns):
        if not vulns:
            return ""
        items = "".join(
            f'<li><span class="cve-badge">{esc_f(v.get("cve_id", v.get("id", "?")))}</span>'
            f' {esc_f(v.get("summary", "")[:120])}'
            f' <span class="muted">({esc_f(v.get("package", ""))})</span></li>'
            for v in vulns[:10]
        )
        if len(vulns) > 10:
            items += f'<li class="muted">... y {len(vulns) - 10} mas</li>'
        return f"<h4>Vulnerabilidades (OSV.dev)</h4><ul class='compact'>{items}</ul>"

    def typo_block(esc_f, typos):
        if not typos:
            return ""
        items = "".join(
            f"<li><code>{esc_f(t.get('domain', ''))}</code> {esc_f(', '.join(t.get('ips', [])))}</li>"
            for t in typos[:10]
        )
        return f"<h4>Typosquatting detectados</h4><ul class='compact'>{items}</ul>"

    def patch_block(esc_f, patching):
        if not patching:
            return ""
        ok_mark = chr(10003)
        warn_mark = chr(9888)
        err_mark = chr(10007)
        items = ""
        for pch in patching[:10]:
            status = pch.get("status", "")
            if status == "current":
                icon = f'<span class="ok">{ok_mark}</span>'
            elif status == "ending":
                icon = f'<span class="warn">{warn_mark}</span>'
            else:
                icon = f'<span class="err">{err_mark}</span>'
            items += f"<li>{icon} <strong>{esc_f(pch.get('technology', ''))}</strong> {esc_f(pch.get('version', '') or '?')} {esc_f(pch.get('detail', ''))}</li>"
        return f"<h4>Patching cadence (endoflife.date)</h4><ul class='compact'>{items}</ul>"

    def supply_block(esc_f, supply):
        if not supply:
            return ""
        ok_mark = chr(10003)
        err_mark = chr(10007)
        items = ""
        for s in (supply or [])[:10]:
            status_html = '<span class="ok">' + ok_mark + ' resuelve</span>' if s.get("resolves") else '<span class="err">' + err_mark + ' no resuelve</span>'
            ips_str = esc_f(", ".join(s.get("ips", [])[:3]) or "")
            items += f'<li><code>{esc_f(s.get("domain", ""))}</code> <span class="muted">({s.get("source", "?")})</span> {status_html} {ips_str}</li>'
        if len(supply) > 10:
            items += f'<li class="muted">... y {len(supply) - 10} mas</li>'
        return f"<h4>Dependencias de terceros (Supply Chain)</h4><ul class='compact'>{items}</ul>"

    def _cert_block(esc_f, tls):
        items = []
        if tls.get("cert_subject"): items.append(f"<li><strong>Subject:</strong> {esc_f(tls['cert_subject'])}</li>")
        if tls.get("cert_issuer"): items.append(f"<li><strong>Issuer:</strong> {esc_f(tls['cert_issuer'])}</li>")
        if tls.get("cert_expiry"): items.append(f"<li><strong>Expira:</strong> {esc_f(tls['cert_expiry'])}</li>")
        if tls.get("cert_serial"): items.append(f"<li><strong>Serial:</strong> {esc_f(tls['cert_serial'])}</li>")
        if tls.get("cert_version"): items.append(f"<li><strong>Version:</strong> {esc_f(tls['cert_version'])}</li>")
        return f"<h4>Detalles del Certificado TLS</h4><ul class='compact'>{''.join(items)}</ul>" if items else ""

    def _redirect_block(esc_f, h):
        chain = h.get("redirect_chain") or []
        if not chain:
            return ""
        items = "".join(f"<li><code>{esc_f(url)}</code></li>" for url in chain[:10])
        return f"<h4>Cadena de Redireccion</h4><ul class='compact'>{items}</ul>"

    def _fingerprint_block(esc_f, h):
        items = []
        if h.get("server_fingerprint"): items.append(f"<li><strong>Server:</strong> {esc_f(h['server_fingerprint'])}</li>")
        if h.get("x_powered_by"): items.append(f"<li><strong>X-Powered-By:</strong> {esc_f(h['x_powered_by'])}</li>")
        if h.get("via"): items.append(f"<li><strong>Via:</strong> {esc_f(h['via'])}</li>")
        if h.get("cf_ray"): items.append(f"<li><strong>CF-Ray:</strong> {esc_f(h['cf_ray'])}</li>")
        return f"<h4>Huella de Servidor</h4><ul class='compact'>{''.join(items)}</ul>" if items else ""

    def _sec_headers_block(esc_f, hdr):
        checks = {"x-frame-options": "X-Frame-Options", "x-content-type-options": "X-Content-Type-Options", "referrer-policy": "Referrer-Policy", "permissions-policy": "Permissions-Policy", "cross-origin-opener-policy": "COOP"}
        items = []
        for key, label in checks.items():
            val = hdr.get(key)
            if val is not None:
                items.append(f"<li><strong>{label}:</strong> <code>{esc_f(val)}</code></li>")
        if not items:
            return ""
        return f"<h4>Cabeceras de Seguridad</h4><ul class='compact'>{''.join(items)}</ul>"

    def takeover_block(esc_f, risks):
        if not risks:
            return ""
        items = ""
        for r in risks[:10]:
            vulnerable = r.get("vulnerable", False)
            badge = '<span class="err">' + chr(10007) + ' VULNERABLE</span>' if vulnerable else '<span class="warn">&#9888; POTENCIAL</span>'
            items += f'<li><code>{esc_f(r.get("host", ""))}</code> &rarr; <code>{esc_f(r.get("cname", ""))}</code> {badge}: {esc_f(r.get("description", ""))}</li>'
        if len(risks) > 10:
            items += f'<li class="muted">... y {len(risks) - 10} mas</li>'
        return f"<h4>Riesgos de Subdomain Takeover</h4><ul class='compact'>{items}</ul>"

    def csp_block(esc_f, findings):
        if not findings:
            return ""
        ok_mark = chr(10003)
        err_mark = chr(10007)
        items = ""
        for f in findings[:10]:
            icon = err_mark if f.get("severity") == "high" else ("&#9888;" if f.get("severity") == "medium" else "&#9679;")
            items += f"<li>{icon} [{f.get('severity','').upper()}] <strong>{esc_f(f.get('directive',''))}</strong>: {esc_f(f.get('description',''))}</li>"
        if len(findings) > 10:
            items += f'<li class="muted">... y {len(findings) - 10} mas</li>'
        return f"<h4>Analisis de CSP</h4><ul class='compact'>{items}</ul>"

    def cookie_block(esc_f, findings):
        if not findings:
            return ""
        ok_mark = chr(10003)
        err_mark = chr(10007)
        items = ""
        for f in findings[:10]:
            icon = err_mark if f.get("severity") == "high" else ("&#9888;" if f.get("severity") == "medium" else "&#9679;")
            items += f"<li>{icon} [{f.get('severity','').upper()}] {esc_f(f.get('description',''))}</li>"
        if len(findings) > 10:
            items += f'<li class="muted">... y {len(findings) - 10} mas</li>'
        return f"<h4>Seguridad de Cookies</h4><ul class='compact'>{items}</ul>"

    def scr_block(esc_f, p):
        scr = p.get("supply_chain_reputation") or {}
        dnsbl = scr.get("dnsbl") or []
        urlhaus = scr.get("urlhaus") or []
        items = ""
        for d in dnsbl[:5]:
            items += f"<li><span class='err'>{chr(10007)} DNSBL: IP {esc_f(d.get('ip',''))} listada en {esc_f(d.get('dnsbl',''))}</span></li>"
        for u in urlhaus[:5]:
            items += f"<li><span class='err'>{chr(10007)} URLhaus: {esc_f(u.get('domain',''))} ({u.get('url_count',0)} urls maliciosas)</span></li>"
        if items:
            return f"<h4>Reputacion de terceros (Supply Chain)</h4><ul class='compact'>{items}</ul>"
        return ""

    def owasp_block(esc_f, m):
        ow = m.get("owasp") or {}
        if not ow:
            return '<h4>OWASP Agentic Top 10</h4><ul class="compact"><li class="muted">Sin evaluacion disponible.</li></ul>'
        grade = ow.get("overall_grade", "—")
        pct = ow.get("overall_compliance", 0)
        items = ""
        ok_mark = chr(10003)
        err_mark = chr(10007)
        for r_id, r_data in sorted((ow.get("risks") or {}).items()):
            if r_data.get("finding_count", 0) > 0:
                icon = err_mark if r_data["compliance_pct"] < 60 else ok_mark
                items += f"<li>{icon} <strong>{r_id}</strong>: Grado {r_data['grade']} ({r_data['compliance_pct']}%) — {r_data['finding_count']} hallazgo(s)</li>"
        if not items:
            items = '<li class="muted">Sin hallazgos que afecten compliance.</li>'
        return f'<h4>OWASP Agentic Top 10 — Grado: {grade} ({pct}%)</h4><ul class="compact">{items}</ul>'

    def social_block(esc_f, p):
        social = p.get("social") or {}
        if not social:
            return '<h4>Redes Sociales (OSINT)</h4><ul class="compact"><li class="muted">Sin datos de redes sociales configurados. Agregue social_* al providers.json.</li></ul>'
        labels = {"instagram": "Instagram", "tiktok": "TikTok", "twitter": "Twitter", "twitch": "Twitch", "telegram": "Telegram", "github": "GitHub"}
        urls = {"instagram": "https://www.instagram.com/", "tiktok": "https://www.tiktok.com/@", "twitter": "https://nitter.net/", "twitch": "https://www.twitch.tv/", "telegram": "https://t.me/", "github": "https://github.com/"}
        items = ""
        for net, data in social.items():
            uname = data.get("username", "")
            err = data.get("error")
            label = labels.get(net, net)
            if err:
                items += f"<li>{label}: @{esc_f(uname)} — error</li>"
            else:
                url = urls.get(net, "") + uname
                followers = str(data.get("followers") or data.get("seguidores") or "")
                desc = str(data.get("description", "") or "")[:120]
                items += f"<li><strong>{label}</strong>: <a href='{esc_f(url)}' target='_blank'>@{esc_f(uname)}</a> · {esc_f(str(data.get('name','') or data.get('full_name','')))} · seguidores: {esc_f(followers)} · {esc_f(desc)}</li>"
        return f"<h4>Redes Sociales (OSINT)</h4><ul class='compact'>{items}</ul>"

    prov_sections = []
    matrix_by_domain = {m.get("dominio", ""): m for m in matrix}
    for p in providers:
        dom = p.get("domain", "")
        ips = ", ".join((p.get("dns") or {}).get("ipv4") or []) or "-"
        h = p.get("https") or {}
        tls = p.get("tls") or {}
        hdr = h.get("headers") or {}
        subs = p.get("subdomains") or []
        crt_subs = p.get("crt_subdomains") or []
        san_list = p.get("san_list") or []
        sub_li = "".join(f"<li><code>{esc(s.get('host'))}</code> {esc(', '.join(s.get('ipv4') or []))}</li>" for s in subs[:25])
        crt_li = "".join(f"<li><code>{esc(s)}</code></li>" for s in crt_subs[:30])
        san_li = "".join(f"<li><code>{esc(s)}</code></li>" for s in san_list[:20])
        dnssec_items = []
        caa = p.get("caa_records") or []
        for rec in caa:
            dnssec_items.append(f"CAA: {esc(rec.get('tag', '?'))} {esc(rec.get('value', '?'))}")
        if p.get("mta_sts"):
            dnssec_items.append(f"MTA-STS: {esc(p['mta_sts'][:120])}")
        if p.get("tls_rpt"):
            dnssec_items.append(f"TLS-RPT: {esc(p['tls_rpt'][:120])}")
        if p.get("bimi"):
            dnssec_items.append(f"BIMI: {esc(p['bimi'][:120])}")

        score = domain_score(p)
        cl_443 = "abierto" if (p.get("port_443") or {}).get("open") else "cerrado"
        cl_80 = "abierto" if (p.get("port_80") or {}).get("open") else "cerrado"
        crt_hdr = '<h4>Subdominios (crt.sh)</h4><ul class="compact">'
        san_hdr = '<h4>SAN</h4><ul class="compact">'
        dnssec_hdr = '<h4>Registros DNS pasivos</h4><ul class="compact"><li>'
        if score >= 90:
            score_cls = "score-a"
        elif score >= 75:
            score_cls = "score-b"
        elif score >= 60:
            score_cls = "score-c"
        elif score >= 45:
            score_cls = "score-d"
        elif score >= 30:
            score_cls = "score-e"
        else:
            score_cls = "score-f"

        prov_sections.append(
            (lambda sc, cl, sl, di, sub_li, crt_li, san_li, dnssec_items: f"""
<section class="card">
  <div class="card-header">
    <div>
      <h3>{esc(p.get("name"))}</h3>
      <p class="meta"><code>{esc(dom)}</code> &middot; {esc(ips)}</p>
    </div>
    <div class="{sc} score-badge">{esc(grade_from_trust(score))}</div>
  </div>
  <div class="kpi-row">
    <span><strong>{score}</strong>/100</span>
    <span>443: {cl_443}</span>
    <span>80: {cl_80}</span>
    <span>Subdominios: {len(subs)}</span>
    <span>crt.sh: {len(crt_subs)}</span>
    <span>SAN: {len(san_list)}</span>
  </div>
  <p><strong>HTTPS:</strong> {esc(h.get("status_code") if isinstance(h.get("status_code"), int) else h.get("error") or "-")} &middot; <strong>TLS:</strong> {esc(tls.get("negotiated_version") or tls.get("error") or "-")} &middot; <strong>Cert. hasta:</strong> {esc(tls.get("cert_expiry") or "-")}</p>
  <h4>Subdominios</h4>
  <ul class="compact">{sub_li or '<li class="muted">Ninguno con el diccionario actual</li>'}</ul>
  {crt_hdr + crt_li + "</ul>" if crt_subs else ""}
  {san_hdr + san_li + "</ul>" if san_list else ""}
  {dnssec_hdr + "</li><li>".join(dnssec_items) + "</li></ul>" if dnssec_items else ""}
  {_cert_block(esc, tls)}
  {_redirect_block(esc, h)}
  {_fingerprint_block(esc, h)}
  {_sec_headers_block(esc, hdr)}
  {vuln_block(esc, p.get("vulnerabilities") or [])}
  {takeover_block(esc, p.get("takeover_risks") or [])}
  {csp_block(esc, p.get("csp_findings") or [])}
  {cookie_block(esc, p.get("cookie_findings") or [])}
  {scr_block(esc, p)}
  {social_block(esc, p)}
  {owasp_block(esc, matrix_by_domain.get(dom, {}))}
  {typo_block(esc, p.get("typosquatting") or [])}
  {patch_block(esc, p.get("patching") or [])}
  {supply_block(esc, p.get("supply_chain") or [])}
  <details>
    <summary class="muted small">Ver cabeceras HTTP</summary>
    <pre class="small">{esc(json.dumps(hdr, indent=2, ensure_ascii=False) if hdr else "{}")}</pre>
  </details>
</section>
""")(score_cls,
    "abierto" if (p.get("port_443") or {}).get("open") else "cerrado",
    "abierto" if (p.get("port_80") or {}).get("open") else "cerrado",
    dom,
    sub_li, crt_li, san_li, dnssec_items)
        )

    matrix_html = ""
    ok_mark = chr(10003)
    err_mark = chr(10007)
    for m in matrix:
        matrix_html += f"""<tr>
 <td>{esc(m.get("proveedor"))}<div class="muted small">{esc(m.get("dominio"))}</div></td>
 <td class="num">{esc(m.get("subdominios"))}</td>
 <td class="num">{m.get("crt_subdominios", 0)}</td>
 <td class="small">{esc(m.get("https"))}</td>
 <td class="c">{ok_mark if m.get("hsts") else err_mark}</td>
 <td class="c">{ok_mark if m.get("csp") else err_mark}</td>
 <td class="num">{m.get("csp_finding_count", 0)}</td>
 <td class="c">{ok_mark if not m.get("cookie_insecure") else err_mark}</td>
 <td class="small">{esc(m.get("spf_dmarc"))}</td>
 <td class="c">{ok_mark if m.get("tls13_negociado") else err_mark}</td>
 <td class="small">{esc(m.get("tls_version"))}</td>
 <td class="c">{ok_mark if m.get("caa") else err_mark}</td>
 <td class="c">{ok_mark if m.get("mta_sts") else err_mark}</td>
 <td class="c">{ok_mark if m.get("tls_rpt") else err_mark}</td>
 <td class="c">{ok_mark if m.get("starttls_ok") else (err_mark if m.get("mx_count", 0) > 0 else "—")}</td>
 <td class="num">{m.get("mx_count", 0)}</td>
 <td class="num">{m.get("ns_count", 0)}</td>
 <td class="c">{ok_mark if m.get("dnssec_ok") else err_mark}</td>
 <td class="num">{m.get("dkim_count", 0)}</td>
 <td class="num">{m.get("dane_count", 0)}</td>
 <td class="c">{ok_mark if m.get("ip_reputation_clean") else esc(str(m.get("ip_reputation_count", 0)))}</td>
 <td class="c">{ok_mark if not m.get("urlhaus_malicious") else err_mark}</td>
 <td class="num">{m.get("vulnerability_count", 0)}</td>
 <td class="num">{m.get("credential_leak_count", 0)}</td>
 <td class="num">{esc(m.get("typosquatting_count", 0))}</td>
  <td class="num">{esc(m.get("patching_eol", 0) + m.get("patching_ending", 0))}</td>
  <td class="c">{ok_mark if m.get("takeover_vulnerable") else (err_mark if m.get("takeover_count", 0) > 0 else "—")}</td>
  <td class="num">{m.get("supply_chain_count", 0)}</td>
  <td class="c">{ok_mark if m.get("supply_reputation_clean") else err_mark}</td>
  </tr>"""

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>{esc(title)} v{esc(version)}</title>
<style>
:root {{
  --red:#FD0D1B; --red-dark:#C4000A; --red-light:#FF4D55;
  --dark:#2C2A29; --dark2:#4A4847;
  --card:#ffffff; --bg:#f5f5f5; --text:#1a1d21; --muted:#6c757d;
  --border:#ddd; --accent:#2C2A29;
  --good:#1a7d4f; --warn:#b8860b; --bad:#b22222;
}}
* {{ box-sizing:border-box; }}
body {{ margin:0; font-family:'Segoe UI',system-ui,sans-serif; background:var(--bg); color:var(--text); line-height:1.5; font-size:13.5px; }}
.wrap {{ max-width:1000px; margin:0 auto; padding:0 0 40px; }}
.header {{
  background:linear-gradient(135deg, var(--red-dark) 0%, var(--red) 60%, var(--red-light) 100%);
  color:#fff; padding:24px 28px 20px;
  display:flex; align-items:center; gap:20px;
}}
.header .logo {{ height:42px; }}
.header h1 {{ margin:0; font-size:1.2rem; font-weight:600; letter-spacing:-0.01em; }}
.header .meta {{ margin:4px 0 0; font-size:12px; opacity:.8; }}
.header .version {{ margin-left:auto; font-size:11px; opacity:.65; text-transform:uppercase; letter-spacing:.08em; }}
.content {{ padding:20px 28px; }}

h2.sec {{
  font-size:1rem; color:var(--red-dark); font-weight:600;
  border-bottom:2px solid var(--red); padding-bottom:5px; margin:28px 0 14px;
  display:flex; align-items:center; gap:8px;
}}
h2.sec::before {{ content:""; display:inline-block; width:4px; height:18px; background:var(--red); border-radius:2px; }}

.card {{
  background:var(--card); border:1px solid var(--border); border-radius:8px;
  padding:16px 18px; margin-bottom:14px;
  box-shadow:0 1px 3px rgba(0,0,0,.04);
}}
.card-header {{
  display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:8px;
}}
.card-header h3 {{ margin:0; font-size:1rem; }}
.meta {{ font-size:12px; color:var(--muted); margin:2px 0 0; }}
.kpi-row {{ display:flex; flex-wrap:wrap; gap:6px 14px; margin:8px 0; font-size:12px; color:var(--muted); }}
.kpi-row strong {{ color:var(--text); }}

.score-badge {{
  width:40px; height:40px; border-radius:50%;
  display:flex; align-items:center; justify-content:center;
  font-weight:700; font-size:18px; color:#fff; flex-shrink:0;
}}
.score-a {{ background:var(--good); }}
.score-b {{ background:#2d8a5e; }}
.score-c {{ background:var(--warn); }}
.score-d {{ background:#cc7a00; }}
.score-e {{ background:#c0392b; }}
.score-f {{ background:var(--bad); }}

.grade-hero {{
  display:flex; align-items:center; gap:16px;
  background:linear-gradient(135deg, var(--red-dark), var(--red));
  color:#fff; padding:16px 20px; border-radius:8px; margin-bottom:14px;
}}
.grade-hero .letter {{ font-size:48px; font-weight:700; line-height:1; opacity:.95; }}
.grade-hero .details {{ font-size:12px; opacity:.85; }}
.grade-hero .trust-score {{ font-size:22px; font-weight:600; }}

table.data {{ width:100%; border-collapse:collapse; font-size:12px; margin-top:6px; }}
table.data th, table.data td {{ border:1px solid var(--border); padding:5px 7px; text-align:left; vertical-align:top; }}
table.data th {{ background:#e9ecef; font-weight:600; font-size:10px; text-transform:uppercase; color:var(--muted); letter-spacing:.04em; }}
table.data .num {{ text-align:right; }}
table.data .c {{ text-align:center; }}

.small {{ font-size:11px; }}
.muted {{ color:var(--muted); }}
.ok {{ color:var(--good); font-weight:600; }}
.warn {{ color:var(--warn); }}
.err {{ color:var(--bad); }}
.sev {{ display:inline-block; padding:1px 7px; border-radius:4px; font-size:10px; font-weight:600; text-transform:uppercase; }}
.sev.high {{ background:#fce4e4; color:var(--bad); }}
.sev.med {{ background:#fff3cd; color:#856404; }}
.sev.low {{ background:#e8f5e9; color:var(--good); }}

pre.small {{ background:#f8fafc; padding:8px; border-radius:6px; overflow:auto; max-height:180px; font-size:11px; border:1px solid var(--border); }}
ul.compact {{ margin:4px 0; padding-left:1.1rem; font-size:12.5px; }}
ul.compact li {{ margin:2px 0; }}
.footnote {{ font-size:11px; color:var(--muted); margin-top:32px; padding-top:12px; border-top:1px solid var(--border); }}
details summary {{ cursor:pointer; }}
details summary:focus {{ outline:none; }}
.cve-badge {{ display:inline-block; background:#e9ecef; padding:0 6px; border-radius:3px; font-family:monospace; font-size:11px; }}
@media print {{
  body {{ background:#fff; }}
  .header {{ -webkit-print-color-adjust:exact; print-color-adjust:exact; }}
  .grade-hero {{ -webkit-print-color-adjust:exact; print-color-adjust:exact; }}
  .score-badge {{ -webkit-print-color-adjust:exact; print-color-adjust:exact; }}
}}
</style>
</head>
<body>
<div class="wrap">
  <div class="header">
    <img class="logo" src="{esc(LOGO_B64)}" alt="Bancolombia"/>
    <div>
      <h1>{esc(title)}</h1>
      <p class="meta">{esc(subtitle)}</p>
    </div>
    <div class="version">v{esc(version)}</div>
  </div>
  <div class="content">
    <div class="grade-hero">
      <div class="letter">{esc(grade)}</div>
      <div>
        <div class="trust-score">{trust}/100</div>
        <div class="details">Grado orientativo (A-F) basado en controles ASM verificables &middot; Escaneo: {esc(gen)}</div>
      </div>
    </div>

    <h2 class="sec">Resumen de evaluacion</h2>
    <div class="card">
      <p>Postura observada por <strong>Attack Surface Management (ASM)</strong> sobre <strong>{n} dominio(s)</strong> de proveedores. Las puntuaciones son indicativas, calculadas a partir de cabeceras HTTP, TLS, DNS (SPF/DMARC), reputacion, vulnerabilidades, typosquatting, patching cadence y dependencias de terceros.</p>
      <div class="kpi-row">
        <span><strong>Activos:</strong> {n}</span>
        <span><strong>Subdominios (DNS):</strong> {total_subs}</span>
        <span><strong>Subdominios (crt.sh):</strong> {total_crt}</span>
        <span><strong>443 abierto:</strong> {open443}/{n}</span>
        <span><strong>80 abierto:</strong> {open80}/{n}</span>
        <span><strong>CAA:</strong> {has_caa}/{n}</span>
        <span><strong>MTA-STS:</strong> {has_mta_sts}/{n}</span>
        <span><strong>CVE detectados:</strong> {total_vulns}</span>
      </div>
    </div>

    <h2 class="sec">Hallazgos</h2>
    <div class="card">
      <table class="data">
        <thead><tr><th>Categoria</th><th>Descripcion</th><th>Proveedores</th><th>Severidad</th></tr></thead>
        <tbody>{risk_table_rows()}</tbody>
      </table>
    </div>

    <h2 class="sec">Factores evaluados</h2>
    <div class="card">
      <p>Este informe evalua los siguientes factores de seguridad:</p>
      <table class="data">
        <thead><tr><th>Factor</th><th>Fuente</th><th>Detalle</th></tr></thead>
        <tbody>
          <tr><td>Configuraciones DNS</td><td>SPF/DMARC, DKIM, DNSSEC, DANE, MX, NS, CAA, MTA-STS, TLS-RPT, BIMI, STARTTLS</td><td>Verifica presencia y correcta configuracion de registros DNS de seguridad y STARTTLS en MX</td></tr>
          <tr><td>SSL/TLS</td><td>Version negociada, vigencia, SAN</td><td>Evalua la fortaleza de la configuracion TLS del servidor web</td></tr>
          <tr><td>Cabeceras HTTP de seguridad</td><td>HSTS, CSP, X-Frame-Options, X-Content-Type-Options</td><td>Detecta cabeceras de seguridad faltantes o mal configuradas</td></tr>
          <tr><td>Analisis de CSP</td><td>Directivas CSP (base-uri, object-src, frame-ancestors, form-action, unsafe-inline/unsafe-eval, comodines, bypass JSONP, report-uri)</td><td>Deteccion de debilidades en la politica de seguridad de contenido</td></tr>
          <tr><td>Seguridad de Cookies</td><td>Flags Secure, HttpOnly, SameSite</td><td>Verificacion de flags de seguridad en cookies HTTP</td></tr>
          <tr><td>Superficie de subdominios</td><td>DNS prefijos + crt.sh + BufferOver + ThreatCrowd</td><td>Descubrimiento pasivo de subdominios y activos expuestos</td></tr>
          <tr><td>Reputacion de IPs</td><td>DNSBL (Spamhaus, Barracuda, SpamCop, SORBS, CBL)</td><td>Verifica si las IPs del dominio estan listadas como maliciosas</td></tr>
          <tr><td>Malware</td><td>URLhaus (Abuse.ch)</td><td>Consulta si el dominio ha sido reportado como distribuidor de malware</td></tr>
          <tr><td>Vulnerabilidades</td><td>OSV.dev</td><td>Deteccion de CVEs asociados a tecnologias y versiones detectadas</td></tr>
          <tr><td>Fugas de credenciales</td><td>leak-lookup.com</td><td>Identifica si el dominio aparece en breaches conocidos (requiere LEAK_API_KEY)</td></tr>
          <tr><td>Typosquatting</td><td>Variantes DNS (TLD, caracteres, omisiones)</td><td>Genera variantes del dominio y verifica si estan activas</td></tr>
          <tr><td>Patching cadence</td><td>endoflife.date</td><td>Determina si las tecnologias detectadas estan EOL o proximas a EOL</td></tr>
          <tr><td>Subdomain Takeover</td><td>CNAME + fingerprints (S3, CloudFront, Heroku, Azure, GitHub Pages, etc.)</td><td>Detecta CNAMEs a servicios externos no configurados o colgantes</td></tr>
          <tr><td>Supply Chain</td><td>CSP headers + HTML scripts</td><td>Extrae dominios de terceros desde CSP y scripts, verifica resolucion DNS</td></tr>
          <tr><td>Reputacion de terceros (Supply Chain)</td><td>DNSBL + URLhaus sobre IPs y dominios de terceros</td><td>Verifica si las IPs y dominios de la cadena de suministro tienen reputacion negativa</td></tr>
        </tbody>
      </table>
    </div>

    <h2 class="sec">Matriz de controles ASM</h2>
    <div class="card" style="overflow:auto">
      <table class="data" style="font-size:10px">
        <thead><tr><th>Proveedor</th><th>Sub</th><th>crt.sh</th><th>HTTPS</th><th>HSTS</th><th>CSP</th><th>CSP-W</th><th>COOK</th><th>SPF/DMARC</th><th>TLS1.3</th><th>TLS</th><th>CAA</th><th>MTA-STS</th><th>TLS-RPT</th><th>STLS</th><th>MX</th><th>NS</th><th>DNSSEC</th><th>DKIM</th><th>DANE</th><th>DNSBL</th><th>URLH</th><th>CVE</th><th>LEAK</th><th>TYPO</th><th>PATCH</th><th>TKO</th><th>SC</th><th>SC-REP</th></tr></thead>
        <tbody>{matrix_html}</tbody>
      </table>
    </div>

    <h2 class="sec">Superficie de ataque por proveedor</h2>
    {"".join(prov_sections)}

    <div class="footnote">
      <p><strong>Bancolombia</strong> &middot; Informe generado el {esc(now)} &middot; Version {esc(version)} &middot; Los datos presentados reflejan el estado en el momento del escaneo y pueden variar.</p>
    </div>
  </div>
</div>
</body>
</html>"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--asm", type=Path, default=ROOT / "asm_report.json")
    ap.add_argument("--out", type=Path, default=ROOT / "informe_bancolombia.html")
    ap.add_argument("--title", default="Third-Party Risk Assessment Report - Bancolombia")
    ap.add_argument("--subtitle", default="Evaluacion ASM del sitio publico Incocredito (host www)")
    ap.add_argument("--version", default="1.0")
    args = ap.parse_args()
    asm = json.loads(args.asm.read_text(encoding="utf-8"))
    html_out = build_report(asm, args.title, args.subtitle, args.version)
    args.out.write_text(html_out, encoding="utf-8")
    print(f"[OK] {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
