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
