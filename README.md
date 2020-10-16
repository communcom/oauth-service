# oauth-service

#### Clone the repository

```bash
git clone https://github.com/communcom/oauth-service.git
cd oauth-service
```

#### Create .env file

```bash
cp .env.example .env
```

Add variables

```bash
FACEBOOK_APP_ID=
FACEBOOK_APP_SECRET=

GOOGLE_CONSUMER_KEY=
GOOGLE_CONSUMER_SECRET=

APPLE_CLIENT_ID_WEB=
APPLE_CLIENT_ID_APP=
APPLE_TEAM_ID=
APPLE_KEY_ID=
APLLE_PRIVATE_KEY=

TELEGRAM_BOT_TOKEN=
```

#### Create docker-compose file

```bash
cp docker-compose.example.yml docker-compose.yml
```

#### Run

```bash
docker-compose up -d --build
```
