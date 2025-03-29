### How to Use This App for Testing Embedded Iframe

1. **Overview**: This app is currently not fully integrated with a frontend and backend to maintain simplicity and ease of understanding. This setup may change in the future.

2. **Start the Server**:

   - Run `bun install` to install dependencies.
   - Start the server with `bun run start`. The server will run on port 3001. Ensure this port is registered as one of your Scalekit environment's redirect URLs.

3. **Access the App**:

   - Open your browser and navigate to `http://localhost:3001/`. You will see a broken iframe initially.

4. **Environment Configuration**:

   - Add a `.env` file in the `/libraries` directory. Use the `.env.example` file as a template.

5. **Organization ID**:

   - The Admin Portal is specific to an organization. Update the hardcoded Organization ID in the `scalekit.js` file with your Scalekit environment's Organization ID.

6. **Generate Portal Links**:

   - Run `bun libraries/scalekit.js` to log portal links to the console. Manually copy the link and update the `src` attribute of the iframe in `public/index.html`.

7. **Content Security Policy**:

   - The iframe will only render if the parent page has a `Content-Security-Policy` header with `frame-ancestors 'self'`. This is a security measure to prevent XSS attacks.

8. **CSP Configuration Shortcut**:

   - Install the [ModHeader extension](https://modheader.com/). Open the extension and configure it to include `Content-Security-Policy` with `self` and `localhost:3001` under the _CSP response modifiers_ section.
   - Just `self` is enough, incase you listed the `localhost:3001` as one of your redirect URLs in your Scalekit environment.

9. **Reload the Page**:
   - After updating the iframe `src` URL, reload the page. Note that the `src` URL is either one-time use or short-lived, so ensure it is updated before reloading.

### Questions

**Can I use `npm` instead of `bun`?**

Yes, you can use `npm` instead of `bun`. Just replace `bun` with `npm` in the instructions above.

Instead of `bun libraries/scalekit.js`, use `node libraries/scalekit.js`.
