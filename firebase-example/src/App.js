import "./App.css";

import {
  Box,
  Button,
  Checkbox,
  Container,
  FormControlLabel,
  FormLabel,
  Grid,
  Link,
  TextField,
  Typography,
} from "@mui/material";
import {
  getAuth,
  getRedirectResult,
  GoogleAuthProvider,
  OAuthProvider,
  signInWithPopup,
  signInWithRedirect,
  signInWithCustomToken,
  signOut,
} from "firebase/auth";
// Using ES6 import syntax
import hljs from "highlight.js/lib/core";
import javascript from "highlight.js/lib/languages/javascript";
import { useState, useEffect } from "react";

// import Cookies from 'universal-cookie';

import Tasks from "./components/Tasks";

// Then register the languages you need
hljs.registerLanguage("javascript", javascript);

function App() {
  const provider = new GoogleAuthProvider();
  const scalekitProvider = new OAuthProvider("oidc.scalekit");
  // const cookies = new Cookies();
  //  provider.addScope("https://www.googleapis.com/auth/contacts.readonly");
  const auth = getAuth();

  const [authorizedUser, setAuthorizedUser] = useState(
    false || sessionStorage.getItem("accessToken")
  );
  // on load of the page check if there is token in request param
  // if yes, use that token to sign in
  useEffect(() => {
    const token = new URLSearchParams(window.location.search).get("token");
    if (token) {
      signInWithCustomToken(auth, token)
        .then((credential) => {
          // The signed-in user info.
          console.log(credential.user);
          const user = credential.user;
          console.log(user);
          const accessToken = credential.accessToken;
          const idToken = credential.idToken;
          console.log(credential);
          sessionStorage.setItem("accessToken", accessToken);

          sessionStorage.setItem("id", user.uid);
          sessionStorage.setItem("Name", user.displayName);
          sessionStorage.setItem("email", user.email);
          sessionStorage.setItem("idToken", idToken);
          setAuthorizedUser(true);
        })
        .catch((error) => {
          console.error(error);
          // ...
        });
    }
  }, []);

  function signInwithSSO() {
    // redirect the user to localhost:5100/sso?email=email-value
    window.location.href = `http://localhost:5100/sso?email=${
      document.getElementById("email").value
    }`;
  }

  function signInwithScalekit() {
    scalekitProvider.setCustomParameters({
      domain: document.getElementById("email").value,
    });

    scalekitProvider.addScope("openid");
    signInWithPopup(auth, scalekitProvider)
      .then((result) => {
        // Get the OAuth access token and ID Token
        const credential = OAuthProvider.credentialFromResult(result);
        // The signed-in user info.
        console.log(credential.idToken);
        const user = result.user.providerData[0];
        console.log(user);
        const accessToken = credential.accessToken;
        const idToken = credential.idToken;
        console.log(credential);
        sessionStorage.setItem("accessToken", accessToken);

        sessionStorage.setItem("id", user.uid);
        sessionStorage.setItem("Name", user.displayName);
        sessionStorage.setItem("email", user.email);
        sessionStorage.setItem("idToken", idToken);
        setAuthorizedUser(true);
      })
      .catch((error) => {
        console.error(error);
        // ...
      });
  }
  function signInwithGoogle() {
    provider.addScope("email");
    signInWithPopup(auth, provider)
      .then((result) => {
        // This gives you a Access Token. You can use it to access the Google
        // API.
        const credential = GoogleAuthProvider.credentialFromResult(result);
        const token = credential.accessToken;
        sessionStorage.setItem("accessToken", token);
        // The signed-in user info.
        // After user is signed in, set the state to true
        console.log(credential);
        const user = result.user;
        console.log(user);
        if (user) {
          user.getIdTokenResult().then((tkn) => {
            // set access token in session storage
            sessionStorage.setItem("idToken", JSON.stringify(tkn));
            console.log(tkn);
            sessionStorage.setItem("id", tkn.claims.sub);
            sessionStorage.setItem("Name", tkn.claims.name);
            sessionStorage.setItem("email", tkn.claims.email);
            setAuthorizedUser(true);
          });
        }
      })
      .catch((error) => {
        // Handle Errors here.
        const errorCode = error.code;
        const errorMessage = error.message;
        // The email of the user's account used.
        const email = error.customData.email;
        // The AuthCredential type that was used.
        const credential = GoogleAuthProvider.credentialFromError(error);
        // ...
      });
  }
  function logoutUser() {
    signOut(auth)
      .then(() => {
        // clear session storage
        sessionStorage.clear();
        setAuthorizedUser(false);
        // window.location.replace("/");
        alert("Logged Out Successfully");
      })
      .catch((error) => {
        // An error happened.
        alert(error);
      });
  }
  return (
    <div className="App">
      {authorizedUser ? (
        <>
          <p>User Logged in!</p>
          <Box className="float-left">
            <FormLabel>ID: </FormLabel>
            <FormLabel>{sessionStorage.getItem("id")}</FormLabel>
          </Box>
          <Box>
            <FormLabel>Name: </FormLabel>
            <FormLabel>{sessionStorage.getItem("Name")}</FormLabel>
          </Box>

          <Box>
            <FormLabel>Email: </FormLabel>
            <FormLabel>{sessionStorage.getItem("email")}</FormLabel>
          </Box>

          <button onClick={logoutUser}>Logout Button</button>
        </>
      ) : (
        <>
          <Container component="main" maxWidth="xs">
            <Box>
              <Typography component="h1" variant="h5">
                Sign In
              </Typography>
              <Box component="form">
                <TextField
                  margin="normal"
                  required
                  fullWidth
                  id="email"
                  type="email"
                  label="Email Address"
                  name="email"
                  autoFocus
                />{" "}
                <Button
                  fullWidth
                  variant="contained"
                  sx={{ mt: 3, mb: 2 }}
                  onClick={signInwithSSO}
                >
                  Sign-in with SSO (Scalekit Direct)
                </Button>
                <Button
                  fullWidth
                  variant="contained"
                  sx={{ mt: 3, mb: 2 }}
                  onClick={signInwithScalekit}
                >
                  Sign-in with SSO (via Firebase)
                </Button>
                <Button
                  fullWidth
                  variant="contained"
                  sx={{ mt: 3, mb: 2 }}
                  onClick={signInwithGoogle}
                >
                  Sign-in with Google
                </Button>
              </Box>
            </Box>
          </Container>
        </>
      )}
    </div>
  );
}

export default App;
