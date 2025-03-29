### Setup

1. Install dependencies

```bash
npm install
```

2. Create a `.env` file with the following variables:

These currently need to be created in `/libraries` directory.

```bash
ENVIRONMENT_URL=
CLIENT_ID=
CLIENT_SECRET=
```

3. Run the server

```bash
npm run dev
```

4. Open your browser and navigate to `http://localhost:4000`

5. Tunnel it.

```bash
svix listen http://localhost:4000
https://play.svix.com/view/c_aZcRiXOpI66Ez1eKsP0PO
```

6. Replace the Organization ID in /scalekit.js with any organization ID and generate a `link.location`.

7. Replace the `link.location` in /public/index.html with the `link.location` you generated.

8. Open your browser and navigate to `http://localhost:4000`

9. Tunnel it.

```bash
svix listen http://localhost:4000
https://play.svix.com/view/c_aZcRiXOpI66Ez1eKsP0PO
```

10. Open your browser and navigate to `https://play.svix.com/view/c_aZcRiXOpI66Ez1eKsP0PO`
