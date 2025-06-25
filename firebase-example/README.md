# Scalekit + Firebase integration for SAML / OIDC based SSO Implementation
If you are currently using Firebase as your authentication platform for password based login or social login methods and want to implement Enterprise SSO using Scalekit, this repo shows how to integrate Scalekit with Firebase in just a few hours and support SAML SSO login and onboard your enterprise customers effectively. 

## Implementation Choices
Firebase and Scalekit can be integrated in multiple ways depending on what you prefer and how you choose to implement. 

### Option 1: Configure Scalekit as an OIDC Provider on Firebase
1. If you are already using Firebase Identity Platform, then this method will be the easiest to implement. All you need to do is configure Scalekit as an OIDC Provider in your Firebase Console and instruct Firebase to choose this provider whenever your customers want to login via SSO. 
2. This documentation clearly articulates how to configure Scalekit as an OpenID provider with Firebase. <https://docs.scalekit.com/integrations/firebase>
3. In the App.js file, you can follow - signInwithScalekit() to see how this works.

### Option 2: Direct SSO Implementation with Custom Tokens on Firebase
1. If you are using Firebase Authentication version and don't want to upgrade to Firebase Identity Platform - then this could be an ideal option for you.
2. In this method, you will integrate your backend directly with Scalekit and fetch the user details from Scalekit after the user successfully logs in via their enterprise identity provider.
3. Using the details fetched from Scalekit - you will create a custom Firebase token and complete the authentication process with Firebase.
4. In the backend/src/index.js - you will see the sample code for how to integrate with Scalekit, how to create custom auth token and complete the authentication flow with Firebase. You can also find the documentation for how to create custom tokens here: <https://firebase.google.com/docs/auth/admin/create-custom-tokens>

## Structure of the sample app
The sample app is structured in two parts
### React App: 
- This react application is meant to show how you can implement a sample login page and use different ways to integrate Login with SSO in your login page.
- If you choose Option 1 to integrate Scalekit direcly as an OIDC provider, running the React Application should be enough to test the end-end login with SSO workflow.

### Express Backend Server:
- This backend server handles the routes to integrate with Scalekit, fetch the user profile, create custom token with firebase and all the other backend functionalities. 
- If you choose Option 2 to integrate Scalekit directly with your backend application - you need to run both the React App and Backend Server 

## Running the React App

```bash
npm install
npm run start
```

## Running the Backend Server

Go to the appropriate backend directory and run the following commands.

1. Make sure to replace the environment variables in the .env file with your own values that you can copy from Scalekit Dashboard.
2. Also copy your Service Account details from your Firebase console and update them in the ServiceAccount.json file.
3. By default, backend server is configured to run on port 5100.

```bash
npm install
npm run dev
```

## License
MIT License

## Credits
We would like to thank Wanuja for creating the base React, Firebase repo that we used to build on top of: <https://github.com/Wanuja97/firebase-authentication-with-react-node-express-article>
