import got from 'got';
import dotenv from 'dotenv';

dotenv.config({ path: '../.env' });

async function getToken() {
  const url = `${process.env.SCALEKIT_ENVIRONMENT_URL}/oauth/token`;

  try {
    const response = await got.post(url, {
      form: {
        client_id: process.env.SCALEKIT_CLIENT_ID,
        client_secret: process.env.SCALEKIT_CLIENT_SECRET,
        grant_type: 'client_credentials',
      },
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });

    const data = JSON.parse(response.body);
    console.log('data', data);
    return data.access_token;
  } catch (error) {
    if (error.response) {
      console.error(error.response.body);
    } else {
      console.error('An error occurred:', error.message);
    }
  }
}
// Example usage
export default getToken;
