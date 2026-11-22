# Advertising seller accounts (ads.txt, sellers.json)

The `Ads-Txt` plugin (`engine/plugins/adstxt`) fetches `https://<apex>/ads.txt`
and `/app-ads.txt` for each in-scope registered domain
(`support.InScopeApexToCheck`, TTL FQDN → Identifier); the catalog is
`internal/semantics/ads_txt.json`.

- **Parsing (`parseAdsTxt`):** `<ad system domain>, <account id>,
  <DIRECT|RESELLER>[, <cert id>]`; comments (`#`) and variable lines
  (`contact=`, `OWNERDOMAIN=`) are skipped. Only DIRECT lines are kept, each
  once, at most `max_accounts`, from a file of at most `max_file_bytes`.
- **Storage:** the file's URL (`URL --domain--> FQDN` to the apex) and, per
  account, `support.StoreFingerprint` with id_type `fingerprint.AdsSeller`
  (`ads_seller`, value `<ad system>:<account id>`), so domains listing the
  same account share one Identifier.
- **sellers.json (`seller`, `parseSellers`):** each ad system's
  `https://<ad system>/sellers.json` is downloaded with
  `support.CachedDownload` into `$TMP/amass-sellers/<ad system>.json` at most
  once per `sellers_ttl_hours`, skipped above `max_sellers_bytes` (25 MB), and
  indexed in memory per day. A matching, non-confidential seller adds
  `seller_name`, `seller_domain` and `seller_type` to the Identifier.

**Evidence (`lens.adsSellerPivot`, from `FindRelatedDomains`):** for each own
apex the stored ads.txt URLs are resolved by URL, and each `ads_seller`
fingerprint not typed `INTERMEDIARY` gives:
- `shared-ads-seller` (strong 0.7): the other domains whose ads.txt carries
  the same Identifier, through `fingerprintSiblings` (now shared by Service
  and URL carriers; same `fpMaxApexes` cap as analytics IDs);
- `ads-seller-domain` (supporting 0.5): the `seller_domain`, when it is
  another domain and not the ad system's own.
