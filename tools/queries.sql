-- Reference queries for the CT mirror SQLite databases.
-- Attach both files first when cross-referencing issuers:
--
--   sqlite3 /Volumes/wd_office_2/datasets/CT/20260506/subjects.db
--   ATTACH '/Volumes/wd_office_2/datasets/CT/20260506/issuers.db' AS idb;

-- ── Basic counts ────────────────────────────────────────────────────────────

SELECT COUNT(*) AS total_subjects FROM subjects;
SELECT COUNT(*) AS total_issuers  FROM issuers;

-- ── Metadata health check ────────────────────────────────────────────────────

SELECT
  COUNT(*)                                              AS total,
  SUM(CASE WHEN organization != '' THEN 1 ELSE 0 END)  AS has_org,
  SUM(CASE WHEN country     != '' THEN 1 ELSE 0 END)   AS has_country,
  SUM(CASE WHEN san_domains != '' THEN 1 ELSE 0 END)   AS has_sans,
  SUM(CASE WHEN san_ips     != '' THEN 1 ELSE 0 END)   AS has_ip_sans,
  SUM(is_wildcard)                                      AS wildcard_certs,
  AVG(san_count)                                        AS avg_san_count,
  MAX(san_count)                                        AS max_san_count,
  SUM(CASE WHEN entry_type = 'precert' THEN 1 ELSE 0 END) AS precerts
FROM subjects;

-- ── Subjects with issuer info (cross-DB join) ────────────────────────────────

SELECT
  s.common_name,
  s.not_before,
  s.not_after,
  s.san_count,
  s.is_wildcard,
  s.country,
  i.common_name  AS issuer,
  i.organization AS issuer_org
FROM subjects s
JOIN idb.issuers i ON s.ca_id = i.ca_id
LIMIT 20;

-- ── Top CAs by certificate count ────────────────────────────────────────────

SELECT
  i.common_name,
  i.organization,
  i.country,
  COUNT(*) AS cert_count
FROM subjects s
JOIN idb.issuers i ON s.ca_id = i.ca_id
GROUP BY s.ca_id
ORDER BY cert_count DESC
LIMIT 20;

-- ── Wildcard certificates ────────────────────────────────────────────────────

SELECT common_name, san_domains, not_after
FROM subjects
WHERE is_wildcard = 1
ORDER BY not_after DESC
LIMIT 20;

-- ── Certificates with IP SANs ────────────────────────────────────────────────

SELECT common_name, san_ips, san_domains
FROM subjects
WHERE san_ips != '' AND san_ips IS NOT NULL
LIMIT 20;

-- ── Certificates expiring within 30 days ────────────────────────────────────

SELECT common_name, not_after, url
FROM subjects
WHERE not_after BETWEEN date('now') AND date('now', '+30 days')
ORDER BY not_after
LIMIT 50;

-- ── High-SAN certs (more than 100 SANs) ─────────────────────────────────────

SELECT common_name, san_count, url
FROM subjects
WHERE san_count > 100
ORDER BY san_count DESC;

-- ── Pre-certificates vs final certificates ───────────────────────────────────

SELECT entry_type, COUNT(*) AS count
FROM subjects
GROUP BY entry_type;

-- ── Unique FQDNs from san_domains (for pipeline export) ─────────────────────
-- SQLite doesn't have a built-in string_split; use the shell export script
-- (tools/export_subdomains.sh) for efficient deduplication across all DBs.
--
-- Single-DB approximation using WITH RECURSIVE to split comma-separated SANs:

WITH RECURSIVE
  san_split(san, rest) AS (
    SELECT
      CASE WHEN instr(san_domains, ',') > 0
           THEN substr(san_domains, 1, instr(san_domains, ',') - 1)
           ELSE san_domains END,
      CASE WHEN instr(san_domains, ',') > 0
           THEN substr(san_domains, instr(san_domains, ',') + 1)
           ELSE '' END
    FROM subjects WHERE san_domains != ''
    UNION ALL
    SELECT
      CASE WHEN instr(rest, ',') > 0
           THEN substr(rest, 1, instr(rest, ',') - 1)
           ELSE rest END,
      CASE WHEN instr(rest, ',') > 0
           THEN substr(rest, instr(rest, ',') + 1)
           ELSE '' END
    FROM san_split WHERE rest != ''
  )
SELECT
  lower(REPLACE(san, '*.', '')) AS fqdn,
  COUNT(*) AS occurrences
FROM san_split
WHERE san != ''
GROUP BY lower(REPLACE(san, '*.', ''))
ORDER BY occurrences DESC
LIMIT 100;

-- ── Country distribution ────────────────────────────────────────────────────

SELECT
  COALESCE(NULLIF(country, ''), '(DV — no country)') AS country,
  COUNT(*) AS count
FROM subjects
GROUP BY country
ORDER BY count DESC;

-- ── Organisation distribution (OV/EV certs only) ────────────────────────────

SELECT organization, country, COUNT(*) AS count
FROM subjects
WHERE organization != ''
GROUP BY organization, country
ORDER BY count DESC
LIMIT 30;

-- ── Tile coverage — entries per tile ─────────────────────────────────────────

SELECT tile_idx, COUNT(*) AS entries
FROM subjects
WHERE tile_idx IS NOT NULL
GROUP BY tile_idx
ORDER BY tile_idx
LIMIT 20;
