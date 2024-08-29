# redborder-mem2incident
This service is part of the Redborder Incident Response Engine. Its task is simple: read keys from Memcached that are used to create and link incidents in the redborder-webui via API.

## Build
```bash
make
```

## Run
```bash
./redborder-mem2incident config.yml
```
