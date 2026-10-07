#!/usr/bin/env python3
"""
OSINT de redes sociales (NetSoc_OSINT port) — extrae info de perfiles públicos
sin API ni cuenta: Instagram, TikTok, Twitter, Twitch, Telegram, GitHub.
"""

from __future__ import annotations

import re
from typing import Any

import requests


def _get(url: str, timeout: int = 20) -> str:
    r = requests.get(url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"})
    r.raise_for_status()
    return r.text


def instagram(username: str) -> dict[str, Any]:
    html = _get(f"https://www.picnob.com/profile/{username}/")
    def _grab(pattern: str, group: int = 1, default: str = "") -> str:
        m = re.search(pattern, html)
        return m.group(group) if m else default
    return {
        "username": username,
        "name": _grab(r'"fullname">([^<]+)'),
        "description": _grab(r'<div class="sum">([^<]+)'),
        "posts": _grab(r'"num">([^<]+)', default="0"),
        "followers": _grab(r'"num">([^<]+)', default="0"),
        "following": _grab(r'"num">([^<]+)', default="0"),
        "private": bool(re.search(r'This account', html)),
        "profile_pic": _grab(r'href="(https://scontent[^"]+)"'),
        "url": f"https://www.instagram.com/{username}",
    }


def tiktok(username: str) -> dict[str, Any]:
    html = _get(f"https://urlebird.com/es/user/{username}/")
    def _grab(pattern: str, group: int = 1, default: str = "") -> str:
        m = re.search(pattern, html)
        return m.group(group) if m else default
    return {
        "username": username,
        "name": _grab(r'<h5 class="text-dark">([^<]+)'),
        "description": _grab(r'<p>([^<]+)'),
        "followers": _grab(r'seguidores[^<]*?>\s*(\d+)', default="0"),
        "following": _grab(r'siguiendo[^<]*?>\s*(\d+)', default="0"),
        "profile_pic": _grab(r'"image"[^"]*"([^"]+)"'),
        "url": f"https://www.tiktok.com/@{username}",
    }


def twitter(username: str) -> dict[str, Any]:
    html = _get(f"https://nitter.net/{username}")
    def _grab(pattern: str, group: int = 1, default: str = "") -> str:
        m = re.search(pattern, html)
        return m.group(group) if m else default
    return {
        "username": username,
        "full_name": _grab(r'og:title[^>]*content="([^"]+)"'),
        "description": _grab(r'og:description[^>]*content="([^"]+)"'),
        "join_date": _grab(r'profile-joindate[^>]*>([^<]+)'),
        "tweets": _grab(r'profile-stat-num[^>]*>([^<]+)', default="0"),
        "following": _grab(r'profile-stat-num[^>]*>([^<]+)', default="0"),
        "followers": _grab(r'profile-stat-num[^>]*>([^<]+)', default="0"),
        "likes": _grab(r'profile-stat-num[^>]*>([^<]+)', default="0"),
        "profile_pic": _grab(r'twitter:image:src[^>]*content="([^"]+)"'),
        "url": f"https://nitter.net/{username}",
    }


def twitch(username: str) -> dict[str, Any]:
    html = _get(f"https://www.twitch.tv/{username}")
    def _grab(pattern: str, group: int = 1, default: str = "") -> str:
        m = re.search(pattern, html)
        return m.group(group) if m else default
    return {
        "username": username,
        "name": _grab(r'<title>([^<]+)'),
        "description": _grab(r'<meta[^>]+name="description"[^>]+content="([^"]+)"'),
        "profile_pic": _grab(r'"url"\s*:\s*"(https://static-cdn[^"]+)"'),
        "url": f"https://www.twitch.tv/{username}",
    }


def telegram(username: str) -> dict[str, Any]:
    html = _get(f"https://t.me/{username}")
    def _grab(pattern: str, group: int = 1, default: str = "") -> str:
        m = re.search(pattern, html)
        return m.group(group) if m else default
    return {
        "username": username,
        "name": _grab(r'<title>([^<]+)'),
        "description": _grab(r'<meta[^>]+name="description"[^>]+content="([^"]+)"'),
        "profile_pic": _grab(r'"url"\s*:\s*"(https://cdn[^"]+)"'),
        "url": f"https://t.me/{username}",
    }


def github(username: str) -> dict[str, Any]:
    html = _get(f"https://github.com/{username}")
    def _grab(pattern: str, group: int = 1, default: str = "") -> str:
        m = re.search(pattern, html)
        return m.group(group) if m else default
    return {
        "username": username,
        "name": _grab(r'<title>([^<]+)'),
        "description": _grab(r'<meta[^>]+name="description"[^>]+content="([^"]+)"'),
        "profile_pic": _grab(r'"url"\s*:\s*"(https://avatars[^"]+)"'),
        "url": f"https://github.com/{username}",
    }


SOCIAL_NETWORKS: dict[str, Any] = {
    "instagram": {"func": instagram, "icon": "Instagram", "field": "instagram"},
    "tiktok": {"func": tiktok, "icon": "TikTok", "field": "tiktok"},
    "twitter": {"func": twitter, "icon": "Twitter", "field": "twitter"},
    "twitch": {"func": twitch, "icon": "Twitch", "field": "twitch"},
    "telegram": {"func": telegram, "icon": "Telegram", "field": "telegram"},
    "github": {"func": github, "icon": "GitHub", "field": "github"},
}


def scan_social(username: str, networks: list[str] | None = None) -> dict[str, Any]:
    results: dict[str, Any] = {}
    targets = networks or list(SOCIAL_NETWORKS.keys())
    for net in targets:
        cfg = SOCIAL_NETWORKS.get(net)
        if not cfg:
            continue
        try:
            data = cfg["func"](username)
            results[net] = data
        except Exception as e:
            results[net] = {"username": username, "error": str(e)}
    return results