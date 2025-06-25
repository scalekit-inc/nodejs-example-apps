const express = require("express");
const cors = require("cors");
const middleware = require("./src/middleware/index");
const { Scalekit } = require("@scalekit-sdk/node");
const admin = require("./src/config/firebase-config");
const dotenv = require("dotenv");
dotenv.config();

const scalekit = new Scalekit(
  process.env.SCALEKIT_ENVIRONMENT_URL,
  process.env.SCALEKIT_CLIENT_ID,
  process.env.SCALEKIT_CLIENT_SECRET
);

const app = express();
const port = process.env.PORT || 5100;
const host = process.env.HOST || "localhost";
const redirectUri =
  process.env.REDIRECT_URI || "http://localhost:5100/callback";
const frontendUrl = process.env.FRONTEND_URL || "http://localhost:3000";

app.use(cors());

app.get("/sso", async (req, res) => {
  const authUrl = scalekit.getAuthorizationUrl(redirectUri, {
    loginHint: req.query.email,
  });
  return res.redirect(authUrl);
});

app.get("/callback", async (req, res) => {
  const { code } = req.query;
  const { user, idToken, accessToken } = await scalekit.authenticateWithCode(
    code,
    redirectUri
  );
  await admin
    .auth()
    .getUserByEmail(user.email)
    .then((userRecord) => {
      // See the UserRecord reference doc for the contents of userRecord.
      admin.auth().updateUser(user.id, {
        email: user.email,
        displayName: user.name,
        disabled: false,
      });
    })
    .catch((error) => {
      // if the user doesn't exist - create a new one;
      if (error.code === "auth/user-not-found") {
        admin.auth().createUser({
          uid: user.id,
          email: user.email,
          displayName: user.name,
          disabled: false,
        });
      }
      console.log("Error fetching user data:", error);
    });
  //create a custom firebase token
  const customToken = await admin.auth().createCustomToken(user.id);
  console.log(customToken);

  // return the custom token to the client
  return res.redirect(`${frontendUrl}/?token=${customToken}`);
});

app.use("/api", middleware.decodeToken);

app.get("/", (req, res) => {
  res.send("Hello World");
});

app.get("/api/tasks", (req, res) => {
  return res.json({
    tasks: [
      {
        title: "Task1",
      },
      {
        title: "Task2",
      },
    ],
  });
});

app.listen(port, () => {
  console.log(`server is running on port ${port}`);
});
