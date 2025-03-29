import { Scalekit } from '@scalekit-sdk/node';
import dotenv from 'dotenv';
import got from 'got';
import getToken from './auth.js';

dotenv.config();

export async function getPortalLink() {
  const orgID = 'org_40103405632356531';
  const accessToken = await getToken();
  const url = `${process.env.SCALEKIT_ENVIRONMENT_URL}/api/v1/organizations/${orgID}/portal_links`;

  try {
    const response = await got.put(url, {
      headers: {
        Accept: 'application/json',
        Authorization: `Bearer ${accessToken}`,
      },
    });
    return JSON.parse(response.body);
  } catch (error) {
    console.error(error);
    throw error;
  }
}

// const scalekit = new Scalekit(
//   process.env.ENVIRONMENT_URL,
//   process.env.CLIENT_ID,
//   process.env.CLIENT_SECRET
// );

// async function generatePortalLink(orgID) {
//   const link = await scalekit.organization.generatePortalLink(orgID);
//   console.log(JSON.stringify(link, null, 2));
// }

// generatePortalLink(orgID);
// // export default generatePortalLink;
