# Traefik to AdGuard

## Description

This project aims to integrate Traefik with AdGuard, allowing for routes populated in Traefik to be updated in the static DNS of AdGuard.

## Installation

1. Clone the repository: `git clone https://github.com/Opachl/traefik-to-AdGuard.git`
2. Install the required dependencies: `pip install -r requirements.txt`
3. Set up the necessary environment variables:

- `UNIFI_URL`: The URL of the AdGuard API
- `IGNORE_SSL_WARNINGS`: true/false iggore ssl warnings from AdGuard API
- `ADGUARD_USERNAME`: The username for accessing the AdGuard API
- `ADGUARD_PASSWORD`: The password for accessing the AdGuard API
- `TRAEFIK_API_URL`: The URL of the Traefik reverse proxy API
- `TRAEFIK_IP`: The IP of the Traefik reverse proxy API
- `ALLOW_DNS_DELETE`: true/false if true it will use the variable DNS_DELETE_DOMAIN to remove all obsolete entrys
- `DNS_DELETE_DOMAIN`: eg. *.myDomain.com will be used for ALLOW_DNS_DELETE wildcard is used to specify wich entrys should be cleaned if not provided by traefik.

## Usage

Install dependencies with `poetry install`

Either via the Docker container or run `poetry run python app.py`. Be sure to have the environment variables listed above available.

## Contributing

Contributions are welcome! Please follow the guidelines outlined in [CONTRIBUTING.md](./CONTRIBUTING.md).

## License

This project is licensed under the [MIT License](./LICENSE).
