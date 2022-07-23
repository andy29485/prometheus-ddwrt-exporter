# prometheus-pmbus-exporter
Currently only supports a few stats that I care about

## Usage
- `cargo build --release`
- copy `target/release/prometheus-ddwrt-exporter` to `/bin`
- copy `prometheus-ddwrt-exporter.env` to `/etc/`
    - change the username/password
- copy `prometheus-ddwrt-exporter@.service` to `/etc/systemd/system`
    - might want to edit the service file to be able to read the env file
- `sudo systemctl enable --now prometheus-pmbus-exporter@192.168.1.1.service`
    - or whatever the ip address of the router is

## TODO
- more stats
- async
    - getting the stats in parallel would be nice...
    - but right now I only get 2 pages, so not really worth it
