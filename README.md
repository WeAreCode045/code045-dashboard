# Code045 Dashboard

Node.js Dashboard + GitHub OAuth SSO voor phpMyAdmin

## Installatie

1. Kopieer `.env.example` naar `.env` en vul je GitHub OAuth gegevens in.
2. Installeer dependencies:
   ```bash
   npm install
   ```
3. Start de server:
   ```bash
   npm start
   ```

## Functionaliteit
- GitHub OAuth login
- User/Server beheer (admin)
- SSO naar phpMyAdmin
- Responsive dashboard met Tailwind CSS

## .env voorbeeld
Zie `.env.example` voor benodigde variabelen.

## Deploy
- Zorg dat poort en callback URL kloppen
- Database wordt automatisch aangemaakt bij eerste run
