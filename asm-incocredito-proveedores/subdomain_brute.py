from __future__ import annotations

import concurrent.futures
import random
import time
from typing import Any

import dns.resolver

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "blog", "webmail", "vpn", "ssh", "smtp",
    "pop3", "imap", "remote", "test", "dev", "api", "app", "stage", "beta",
    "demo", "shop", "store", "portal", "secure", "support", "help", "status",
    "docs", "wiki", "forum", "community", "m", "mobile", "mobil", "wap",
    "autodiscover", "cpanel", "whm", "webdisk", "cpcalendars", "cpcontacts",
    "direct-connect", "email", "exim", "hostmaster", "lists", "manager",
    "members", "mysql", "newsletter", "ns1", "ns2", "ns3", "ns4", "owa",
    "panel", "phpmyadmin", "pma", "postmaster", "registrar", "root", "server",
    "sql", "ssl", "static", "stats", "survey", "tracking", "uploads", "web",
    "webservice", "www2", "www3", "www4", "wwww", "my", "you", "club",
    "info", "site", "sites", "wordpress", "wp", "blogspot", "crm", "erp",
    "hr", "intranet", "extranet", "git", "svn", "jenkins", "jira", "confluence",
    "nexus", "artifactory", "docker", "k8s", "kubernetes", "grafana", "prometheus",
    "kibana", "elastic", "logstash", "splunk", "zabbix", "nagios", "sensu",
    "datadog", "newrelic", "sonar", "sonarqube", "coverity", "fortify",
    "bugzilla", "mantis", "redmine", "taiga", "trello", "slack", "teams",
    "zoom", "meet", "webex", "gotomeeting", "skype", "lync", "sip",
    "jabber", "xmpp", "chat", "discord", "matrix", "element", "riot",
    "iris", "sso", "oauth", "auth", "login", "signin", "signup", "register",
    "account", "accounts", "profile", "user", "users", "customer", "clients",
    "partner", "partners", "vendor", "vendors", "supplier", "suppliers",
    "contractor", "contractors", "pay", "payment", "payments", "billing",
    "invoice", "invoices", "checkout", "cart", "shop", "order", "orders",
    "track", "tracking", "ship", "shipping", "delivery", "returns", "refund",
    "help", "faq", "knowledgebase", "kb", "ticket", "tickets", "support",
    "service", "services", "desk", "freshdesk", "zendesk", "helpdesk",
    "career", "careers", "jobs", "job", "apply", "recruit", "recruitment",
    "hr", "human-resources", "employee", "employees", "staff", "team",
    "about", "contact", "terms", "privacy", "policy", "legal", "dmca",
    "press", "news", "media", "gallery", "photo", "photos", "image", "images",
    "video", "videos", "tv", "radio", "stream", "live", "tv", "play",
    "player", "music", "audio", "podcast", "podcasts", "rss", "feed", "feeds",
    "download", "downloads", "upload", "uploads", "files", "file", "asset",
    "assets", "resource", "resources", "static", "static2", "static3",
    "cdn", "cdn2", "cdn3", "cloud", "cloudfront", "s3", "storage", "backup",
    "backups", "mirror", "mirrors", "cache", "proxy", "redirect", "redirects",
    "lb", "loadbalancer", "load-balancer", "haproxy", "nginx", "apache",
    "tomcat", "jetty", "jboss", "weblogic", "websphere", "glassfish",
    "payara", "wildfly", "undertow", "gunicorn", "uwsgi", "passenger",
    "node", "nodejs", "python", "django", "flask", "rails", "ruby",
    "php", "asp", "aspx", "jsp", "cgi", "fastcgi", "wsgi", "fcgi",
    "swagger", "api-docs", "api-documentation", "api-doc", "swagger-ui",
    "redoc", "graphql", "graphiql", "playground", "rest", "soap", "xmlrpc",
    "jsonrpc", "grpc", "websocket", "ws", "wss", "mqtt", "amqp", "stomp",
    "iot", "edge", "fog", "sensor", "sensors", "device", "devices",
    "gateway", "hub", "bridge", "connector", "connectors", "adapter", "adapters",
    "sync", "synchronization", "replication", "replica", "replicas",
    "master", "slave", "primary", "secondary", "standby", "failover",
    "active", "passive", "dr", "disaster-recovery", "backup", "restore",
    "archive", "archives", "retention", "retire", "retired", "sunset",
    "sandbox", "playground", "lab", "labs", "research", "rd", "innovation",
    "prototype", "prototypes", "poc", "proof-of-concept", "mvp",
    "alpha", "beta", "gamma", "delta", "epsilon", "nightly", "daily",
    "weekly", "release", "releases", "hotfix", "hotfixes", "patch", "patches",
    "update", "updates", "upgrade", "upgrades", "migration", "migrate",
    "import", "export", "data", "database", "db", "nosql", "redis",
    "memcache", "memcached", "varnish", "squid", "traffic-server",
    "akamai", "fastly", "cloudflare", "cloudfront", "incapsula",
    "ddos", "ddos-protection", "waf", "firewall", "ips", "ids",
    "honeypot", "honeypots", "trap", "traps", "sandbox", "detection",
    "prevention", "security", "secure", "safe", "trust", "trusted",
    "verify", "verification", "validate", "validation", "confirm",
    "confirmation", "2fa", "two-factor", "mfa", "otp", "totp",
    "recaptcha", "captcha", "hcaptcha", "turnstile",
    "analytics", "analytics", "piwik", "matomo", "ga", "google-analytics",
    "gtm", "tag-manager", "pixel", "pixels", "conversion", "conversions",
    "tracker", "trackers", "beacon", "beacons", "webhook", "webhooks",
    "callback", "callbacks", "endpoint", "endpoints", "webhook",
    "events", "event", "notification", "notifications", "alert", "alerts",
    "sms", "email", "mailer", "mailgun", "sendgrid", "postmark", "ses",
    "sparkpost", "mailchimp", "mailjet", "mandrill", "mailer",
    "push", "pusher", "onesignal", "firebase", "fcm", "apns", "gcm",
    "inbox", "outbox", "draft", "drafts", "spam", "trash", "sent",
    "calendar", "cal", "caldav", "carddav", "contacts", "addressbook",
    "drive", "files", "documents", "spreadsheet", "presentation",
    "office", "word", "excel", "powerpoint", "onenote", "outlook",
    "sharepoint", "teams", "yammer", "planner", "tasks", "todo",
    "notes", "onenote", "evernote", "notion", "confluence",
    "monitor", "monitoring", "watchdog", "watch", "observer",
    "dashboard", "dash", "metrics", "metric", "stats", "statistics",
    "report", "reports", "reporting", "analytics", "insights",
    "audit", "audits", "auditor", "compliance", "governance",
    "risk", "risks", "control", "controls", "policy", "policies",
    "sla", "slo", "sli", "kpi", "kpis", "okr", "okrs",
    "performance", "perf", "benchmark", "benchmarks", "loadtest",
    "stress", "stress-test", "chaos", "chaos-engineering",
    "license", "licenses", "licensing", "subscription", "subscriptions",
    "trial", "trials", "demo", "demos", "free", "premium", "enterprise",
    "pro", "basic", "starter", "standard", "advanced", "ultimate",
    "community", "open", "opensource", "source", "code", "coding",
    "github", "gitlab", "bitbucket", "gitea", "gogs", "pagure",
    "ci", "cd", "cicd", "pipeline", "pipelines", "build", "builds",
    "compile", "compilation", "test", "tests", "testing", "qa",
    "quality", "quality-assurance", "uat", "staging", "stage",
    "production", "prod", "preprod", "pre-production", "postprod",
    "canary", "blue", "green", "red", "black", "gold", "silver",
    "us", "eu", "asia", "apac", "emea", "amer", "latam", "na", "sa",
    "region1", "region2", "zone1", "zone2", "az1", "az2", "az3",
    "cell1", "cell2", "cluster1", "cluster2", "node1", "node2",
    "instance1", "instance2", "server1", "server2", "host1", "host2",
    "vm1", "vm2", "container1", "container2", "pod1", "pod2",
    "worker1", "worker2", "broker1", "broker2", "queue1", "queue2",
    "topic1", "topic2", "partition1", "partition2", "segment1", "segment2",
    "shard1", "shard2", "db1", "db2", "db3", "db-primary", "db-secondary",
    "db-replica", "db-slave", "db-master", "ro", "rw", "read", "write",
    "readonly", "readwrite", "writeonly", "reporting", "etl", "olap",
    "oltp", "datawarehouse", "dw", "dwh", "lake", "datalake",
    "stream", "streaming", "kafka", "pulsar", "rabbitmq", "activemq",
    "nats", "nsq", "zeromq", "pubsub", "queue", "queues",
    "spark", "hadoop", "hive", "hbase", "cassandra", "mongo", "mongodb",
    "elasticsearch", "es", "solr", "lucene", "sphinx", "algolia",
    "meilisearch", "typesense", "weaviate", "pinecone", "qdrant",
    "neo4j", "orientdb", "arangodb", "couchdb", "couchbase", "riak",
    "dynamo", "dynamodb", "cosmos", "cosmosdb", "bigtable", "bigquery",
    "redshift", "snowflake", "athena", "glue", "crawler", "crawlers",
    "function", "functions", "lambda", "faas", "serverless", "step",
    "stepfunction", "workflow", "workflows", "orchestrator",
    "scheduler", "cron", "cronjob", "task", "tasks", "job", "jobs",
    "batch", "bulk", "mass", "massive", "parallel", "distributed",
    "grid", "cluster", "supercomputer", "hpc", "compute", "cpu",
    "gpu", "tpu", "npu", "fpga", "asic", "accelerator",
]

RESOLVERS = [
    "1.1.1.1", "1.0.0.1",
    "8.8.8.8", "8.8.4.4",
    "9.9.9.9", "149.112.112.112",
    "208.67.222.222", "208.67.220.220",
    "8.26.56.26", "8.20.247.20",
    "64.6.64.6", "64.6.65.6",
    "77.88.8.8", "77.88.8.1",
    "76.76.19.19", "76.223.122.150",
    "94.140.14.14", "94.140.15.15",
    "185.228.168.9", "185.228.169.9",
    "156.154.70.1", "156.154.71.1",
    "45.90.28.190", "45.90.30.190",
]


def _resolve_subdomain(subdomain: str, domain: str, resolver_ips: list[str]) -> dict[str, Any] | None:
    fqdn = f"{subdomain}.{domain}"
    for resolver_ip in random.sample(resolver_ips, min(3, len(resolver_ips))):
        try:
            r = dns.resolver.Resolver()
            r.nameservers = [resolver_ip]
            r.timeout = 3
            r.lifetime = 4
            answers = r.resolve(fqdn, "A", lifetime=4)
            ips = [str(a) for a in answers]
            cname = ""
            try:
                cname_answers = r.resolve(fqdn, "CNAME", lifetime=3)
                cname = str(cname_answers[0].target)
            except Exception:
                pass
            return {"subdomain": subdomain, "fqdn": fqdn, "ips": ips, "cname": cname}
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.LifetimeTimeout, dns.exception.Timeout):
            continue
        except Exception:
            continue
    return None


def brute_subdomains(domain: str, wordlist: list[str] | None = None,
                     max_workers: int = 100, timeout: int = 60) -> list[dict[str, Any]]:
    resolver_ips = RESOLVERS[:]
    random.shuffle(resolver_ips)
    words = wordlist or COMMON_SUBDOMAINS
    found: list[dict[str, Any]] = []
    start = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_resolve_subdomain, w, domain, resolver_ips): w for w in words}
        for future in concurrent.futures.as_completed(futures, timeout=timeout):
            if time.time() - start > timeout:
                break
            result = future.result()
            if result:
                found.append(result)

    found.sort(key=lambda x: x["subdomain"])
    return found
