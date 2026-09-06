# BrowserAlert — Logbook

Learnings and landmines. How to use this module: [README.md](README.md).

---

## Landmines

### Successful approaches
- Chrome policy enforcement through macOS defaults
- Remote SSH access for automated monitoring
- SQLite-based history analysis
- Router-level content blocking

### Failed attempts

#### DNS-Based Filtering
- Attempted `/private/etc/hosts` modification
- Tried forcing SafeSearch via forcesafesearch.google.com
- Reference: [OpenDNS SafeSearch Guide](https://support.opendns.com/hc/en-us/articles/227986807-How-to-Enforcing-Google-SafeSearch-YouTube-and-Bing)
- Issues: Redirects became messy, multiple redirect chains to the router

#### DNS Cache Management
```bash
sudo dscacheutil -flushcache
sudo killall -HUP mDNSResponder
```
Also tried: `chrome://net-internals/#dns`

#### Apache-Based Blocking
Attempted redirect configuration:
```apache
# /etc/apache2/sites-enabled/000-default.conf
ErrorDocument 404 http://<block-page-host>:30000/shn_blocking.html?cat_id=100&domain=blocked/

# Test and restart
sudo apache2ctl configtest
sudo service apache2 restart
```

---

## Future Improvements

- Compress JSON and CSV log files for storage efficiency
- Implement automated alerting based on browsing patterns
- Add web dashboard for monitoring overview
- Integrate with time-based access controls
