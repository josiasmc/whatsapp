# Deployment Guide

## Docker Image

Registry: `code.induso.cr`
Repository: `induso/mautrix-whatsapp`
Full image name: `code.induso.cr/induso/mautrix-whatsapp:<version>`

### Prerequisites

- Docker installed and running
- Authenticated to the registry:
  ```sh
  docker login code.induso.cr
  ```

### Build and Push

Replace `<version>` with the desired tag (e.g. `1.0.0`, `latest`, or a git SHA).

```sh
# Build
docker build -t code.induso.cr/induso/mautrix-whatsapp:<version> -f ./Dockerfile .

# Push
docker push code.induso.cr/induso/mautrix-whatsapp:<version>
```

Or via the Makefile, overriding `APP_NAME`:

```sh
make docker APP_NAME=code.induso.cr/induso/mautrix-whatsapp:<version>
```

#### Tag `latest` alongside a versioned release

```sh
docker build -f ./Dockerfile \
  -t code.induso.cr/induso/mautrix-whatsapp:<version> \
  -t code.induso.cr/induso/mautrix-whatsapp:latest \
  .

docker push code.induso.cr/induso/mautrix-whatsapp:<version>
docker push code.induso.cr/induso/mautrix-whatsapp:latest
```
