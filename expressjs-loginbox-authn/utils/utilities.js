import { Scalekit } from '@scalekit-sdk/node';

const requiredEnvVars = [
  'SCALEKIT_ENVIRONMENT_URL',
  'SCALEKIT_CLIENT_ID',
  'SCALEKIT_CLIENT_SECRET',
];

export function validateEnvironmentVariables() {
  const missingEnvVars = requiredEnvVars.filter(
    (varName) => !process.env[varName]
  );

  if (missingEnvVars.length > 0) {
    console.error('\n❌ Missing required environment variables:');
    missingEnvVars.forEach((varName) => {
      console.error(`   - ${varName}`);
    });
    console.error('\nPlease create a .env file with the following variables:');
    console.error('SCALEKIT_ENVIRONMENT_URL=your_environment_url');
    console.error('SCALEKIT_CLIENT_ID=your_client_id');
    console.error('SCALEKIT_CLIENT_SECRET=your_client_secret');
    console.error('\nYou can get these values from your Scalekit dashboard.\n');
    process.exit(1);
  }

  try {
    let scalekit = new Scalekit(
      process.env.SCALEKIT_ENVIRONMENT_URL,
      process.env.SCALEKIT_CLIENT_ID,
      process.env.SCALEKIT_CLIENT_SECRET
    );

    console.info('Environment variables validated successfully');

    return scalekit;
  } catch (error) {
    console.error('❌ Error initializing ScaleKit:', error);
    process.exit(1);
  }
}

let scalekit = new Scalekit(
  process.env.SCALEKIT_ENVIRONMENT_URL,
  process.env.SCALEKIT_CLIENT_ID,
  process.env.SCALEKIT_CLIENT_SECRET
);

verifyPasswordlessEmail();

async function testPasswordless() {
  try {
    let res = await scalekit.passwordless.sendPasswordlessEmail(
      'saifshine7@gmail.com',
      {
        template: 'SIGNIN',
        state: '1234567890',
        expiresIn: 100,
        magic
      }
    );

    console.log(res);
  } catch (error) {
    console.error('❌ Error sending passwordless email:', error);
  }
}

async function resendPasswordlessEmail() {
  let response = await scalekit.passwordless.resendPasswordlessEmail(
    authRequestId
  );

  console.log(response);
}

async function verifyPasswordlessEmail() {
  let response = await scalekit.passwordless.verifyPasswordlessEmail(
    'nynDqEx2vM8RWjT0-4sYa5ZJd1vs07dSJ3Hnhn6vnvSRTsTE_A',
    {
      code: '618058',
    }
  );
  console.log(response);
}
